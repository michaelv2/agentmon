"""Configuration loading for agentmon.

Loads settings from TOML config file with CLI override support.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import tomli

logger = logging.getLogger(__name__)


def get_default_config_path() -> Path:
    """Get the default config file path."""
    return Path.home() / ".config" / "agentmon" / "agentmon.toml"


def get_config_search_paths() -> list[Path]:
    """Get list of paths to search for config file."""
    return [
        Path("agentmon.toml"),  # Current directory
        Path.home() / ".config" / "agentmon" / "agentmon.toml",
        Path("/etc/agentmon/agentmon.toml"),
    ]


def find_config_file() -> Optional[Path]:
    """Find the first existing config file."""
    for path in get_config_search_paths():
        if path.exists():
            return path
    return None


@dataclass
class Config:
    """Loaded configuration with all sections."""

    # Database
    db_path: Path = field(default_factory=lambda: Path.home() / ".local" / "share" / "agentmon" / "events.db")

    # Syslog
    syslog_port: int = 1514
    syslog_protocol: str = "tcp"
    syslog_bind_address: str = "0.0.0.0"
    syslog_allowed_ips: list[str] = field(default_factory=list)

    # Analyzer
    entropy_threshold: float = 3.5
    entropy_min_length: int = 10
    learning_mode: bool = False
    known_bad_patterns: list[str] = field(default_factory=list)
    allowlist: set[str] = field(default_factory=set)
    ignore_suffixes: list[str] = field(default_factory=lambda: [
        ".local", ".lan", ".home", ".internal", ".localdomain", ".arpa"
    ])

    # LLM
    llm_enabled: bool = False
    llm_model: str = "llama3.3:70b"

    # Alerting
    min_severity: str = "low"


def load_config(config_path: Optional[Path] = None) -> Config:
    """Load configuration from TOML file.

    Args:
        config_path: Explicit path to config file, or None to search

    Returns:
        Config object with loaded values
    """
    config = Config()

    # Find config file
    if config_path is None:
        config_path = find_config_file()

    if config_path is None or not config_path.exists():
        logger.debug("No config file found, using defaults")
        return config

    logger.info(f"Loading config from {config_path}")

    try:
        with open(config_path, "rb") as f:
            data = tomli.load(f)
    except Exception as e:
        logger.warning(f"Failed to load config file: {e}")
        return config

    # Database section
    if "database" in data:
        db = data["database"]
        if "path" in db:
            config.db_path = Path(db["path"]).expanduser()

    # Syslog section
    if "syslog" in data:
        syslog = data["syslog"]
        if "port" in syslog:
            config.syslog_port = syslog["port"]
        if "protocol" in syslog:
            config.syslog_protocol = syslog["protocol"]
        if "bind_address" in syslog:
            config.syslog_bind_address = syslog["bind_address"]
        if "allowed_ips" in syslog:
            config.syslog_allowed_ips = syslog["allowed_ips"]

    # Analyzer section
    if "analyzer" in data:
        analyzer = data["analyzer"]
        if "entropy_threshold" in analyzer:
            config.entropy_threshold = analyzer["entropy_threshold"]
        if "entropy_min_length" in analyzer:
            config.entropy_min_length = analyzer["entropy_min_length"]
        if "learning_mode" in analyzer:
            config.learning_mode = analyzer["learning_mode"]
        if "known_bad_patterns" in analyzer:
            config.known_bad_patterns = analyzer["known_bad_patterns"]
        if "allowlist" in analyzer:
            config.allowlist = set(analyzer["allowlist"])
        if "ignore_suffixes" in analyzer:
            config.ignore_suffixes = analyzer["ignore_suffixes"]

    # LLM section
    if "llm" in data:
        llm = data["llm"]
        if "enabled" in llm:
            config.llm_enabled = llm["enabled"]
        if "model" in llm:
            config.llm_model = llm["model"]

    # Alerting section
    if "alerting" in data:
        alerting = data["alerting"]
        if "min_severity" in alerting:
            config.min_severity = alerting["min_severity"]

    return config


def merge_cli_options(config: Config, **cli_options: Any) -> Config:
    """Merge CLI options into config (CLI takes precedence).

    Args:
        config: Base config from file
        **cli_options: CLI option overrides (None values are ignored)

    Returns:
        Config with CLI overrides applied
    """
    # Map CLI option names to config attributes
    mappings = {
        "port": "syslog_port",
        "protocol": "syslog_protocol",
        "bind": "syslog_bind_address",
        "allow": "syslog_allowed_ips",
        "learning": "learning_mode",
        "llm": "llm_enabled",
        "llm_model": "llm_model",
        "db": "db_path",
    }

    for cli_name, config_name in mappings.items():
        if cli_name in cli_options:
            value = cli_options[cli_name]
            # Only override if CLI value is meaningful
            if value is not None and value != () and value != "":
                if cli_name == "allow" and isinstance(value, tuple):
                    value = list(value)
                if cli_name == "db" and value:
                    value = Path(value)
                setattr(config, config_name, value)

    return config
