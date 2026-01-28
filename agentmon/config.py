"""Configuration loading for agentmon.

Loads settings from TOML config file with CLI override support.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import tomli

from agentmon.models import Severity
from agentmon.policies.models import Device, ParentalPolicy, TimeRule

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
    syslog_bind_address: str = "127.0.0.1"  # Localhost only by default for security
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
    alert_dedup_window: int = 600  # 10 minutes

    # LLM (two-tier)
    llm_enabled: bool = False
    llm_triage_model: str = "phi3:3.8b"
    llm_escalation_model: str = "gpt-oss:20b"
    llm_downgrade_enabled: bool = True
    llm_downgrade_confidence: float = 0.8

    # Alerting
    min_severity: str = "low"

    # Slack
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    slack_min_severity: str = "medium"

    # Parental Controls
    parental_controls_enabled: bool = False
    parental_devices: list[Device] = field(default_factory=list)
    parental_policies: dict[str, ParentalPolicy] = field(default_factory=dict)

    # Device Activity Anomaly Detection
    device_activity_enabled: bool = False
    device_activity_learning_days: int = 14
    device_activity_threshold: int = 5
    device_activity_min_samples: int = 7
    device_activity_severity: str = "medium"
    device_activity_devices: list[dict] = field(default_factory=list)

    # Client Identity Resolution
    resolver_enabled: bool = False
    resolver_dns_server: Optional[str] = None
    resolver_cache_ttl: int = 3600  # 1 hour
    resolver_strip_suffix: bool = True
    resolver_mappings: dict[str, str] = field(default_factory=dict)

    # Data Retention Policy
    retention_enabled: bool = False
    retention_dns_events_days: int = 30
    retention_alerts_days: int = 90
    retention_cleanup_interval_hours: int = 24


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
        if "alert_dedup_window" in analyzer:
            config.alert_dedup_window = analyzer["alert_dedup_window"]

    # LLM section
    if "llm" in data:
        llm = data["llm"]
        if "enabled" in llm:
            config.llm_enabled = llm["enabled"]
        if "triage_model" in llm:
            config.llm_triage_model = llm["triage_model"]
        if "escalation_model" in llm:
            config.llm_escalation_model = llm["escalation_model"]
        # Backwards compatibility: single "model" sets both
        if "model" in llm and "triage_model" not in llm:
            config.llm_triage_model = llm["model"]
            config.llm_escalation_model = llm["model"]
        if "downgrade_enabled" in llm:
            config.llm_downgrade_enabled = llm["downgrade_enabled"]
        if "downgrade_confidence" in llm:
            config.llm_downgrade_confidence = llm["downgrade_confidence"]

    # Alerting section
    if "alerting" in data:
        alerting = data["alerting"]
        if "min_severity" in alerting:
            config.min_severity = alerting["min_severity"]

    # Slack section
    if "slack" in data:
        slack = data["slack"]
        if "enabled" in slack:
            config.slack_enabled = slack["enabled"]
        if "webhook_url" in slack:
            config.slack_webhook_url = slack["webhook_url"]
        if "min_severity" in slack:
            config.slack_min_severity = slack["min_severity"]

    # Parental Controls section
    if "parental_controls" in data:
        pc = data["parental_controls"]
        if "enabled" in pc:
            config.parental_controls_enabled = pc["enabled"]

        # Parse policies first (devices reference them by name)
        if "policies" in pc:
            for policy_name, policy_data in pc["policies"].items():
                time_rules = []
                if "time_rules" in policy_data:
                    for rule_data in policy_data["time_rules"]:
                        time_rules.append(
                            TimeRule(
                                start=rule_data.get("start", "00:00"),
                                end=rule_data.get("end", "23:59"),
                                days=rule_data.get("days", []),
                                allowed_categories=rule_data.get("allowed_categories"),
                            )
                        )

                severity_str = policy_data.get("alert_severity", "medium")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM

                config.parental_policies[policy_name] = ParentalPolicy(
                    name=policy_name,
                    description=policy_data.get("description", ""),
                    blocked_categories=policy_data.get("blocked_categories", []),
                    allowed_domains=policy_data.get("allowed_domains", []),
                    time_rules=time_rules,
                    alert_severity=severity,
                )

        # Parse devices
        if "devices" in pc:
            for device_data in pc["devices"]:
                config.parental_devices.append(
                    Device(
                        name=device_data.get("name", "unknown"),
                        client_ips=device_data.get("client_ips", []),
                        policy_name=device_data.get("policy", ""),
                    )
                )

    # Device Activity Anomaly Detection section
    if "device_activity" in data:
        da = data["device_activity"]
        if "enabled" in da:
            config.device_activity_enabled = da["enabled"]
        if "learning_days" in da:
            config.device_activity_learning_days = da["learning_days"]
        if "activity_threshold" in da:
            config.device_activity_threshold = da["activity_threshold"]
        if "min_samples" in da:
            config.device_activity_min_samples = da["min_samples"]
        if "alert_severity" in da:
            config.device_activity_severity = da["alert_severity"]

        # Parse named devices
        if "devices" in da:
            for device_data in da["devices"]:
                config.device_activity_devices.append({
                    "name": device_data.get("name", "unknown"),
                    "client_ips": device_data.get("client_ips", []),
                    "always_active": device_data.get("always_active", False),
                })

    # Client Identity Resolution section
    if "client_resolver" in data:
        cr = data["client_resolver"]
        if "enabled" in cr:
            config.resolver_enabled = cr["enabled"]
        if "dns_server" in cr:
            config.resolver_dns_server = cr["dns_server"]
        if "cache_ttl" in cr:
            config.resolver_cache_ttl = cr["cache_ttl"]
        if "strip_suffix" in cr:
            config.resolver_strip_suffix = cr["strip_suffix"]

        # Parse explicit IP -> hostname mappings
        if "mappings" in cr:
            for mapping in cr["mappings"]:
                ip = mapping.get("ip")
                name = mapping.get("name")
                if ip and name:
                    config.resolver_mappings[ip] = name

    # Data Retention Policy section
    if "retention" in data:
        ret = data["retention"]
        if "enabled" in ret:
            config.retention_enabled = ret["enabled"]
        if "dns_events_days" in ret:
            config.retention_dns_events_days = ret["dns_events_days"]
        if "alerts_days" in ret:
            config.retention_alerts_days = ret["alerts_days"]
        if "cleanup_interval_hours" in ret:
            config.retention_cleanup_interval_hours = ret["cleanup_interval_hours"]

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
