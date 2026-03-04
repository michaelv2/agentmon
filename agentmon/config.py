"""Configuration loading for agentmon.

Loads settings from TOML config file with CLI override support.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import tomli

from agentmon.models import Severity
from agentmon.policies.models import Device, ParentalPolicy, TimeRule

logger = logging.getLogger(__name__)

# Environment variable names for sensitive settings
ENV_SLACK_WEBHOOK = "AGENTMON_SLACK_WEBHOOK"
ENV_OLLAMA_HOST = "OLLAMA_HOST"
ENV_VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY"
ENV_ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"


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

    # VirusTotal
    virustotal_api_key: Optional[str] = None

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

    # Threat Intelligence Feeds
    threat_feeds_enabled: bool = False
    threat_feeds_cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "agentmon" / "feeds")
    threat_feeds_update_interval_hours: int = 24
    threat_feeds_severity: str = "high"

    # Dashboard
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080

    # Volume Anomaly Detection
    volume_anomaly_enabled: bool = False
    volume_anomaly_learning_days: int = 14
    volume_anomaly_sensitivity_sigma: float = 3.0
    volume_anomaly_min_samples: int = 7
    volume_anomaly_min_query_threshold: int = 20
    volume_anomaly_min_domain_threshold: int = 10
    volume_anomaly_sustained_hours: int = 3
    volume_anomaly_spike_severity: str = "medium"
    volume_anomaly_diversity_severity: str = "high"
    volume_anomaly_sustained_severity: str = "high"
    volume_anomaly_devices: list[dict] = field(default_factory=list)

    # OODA Watchdog
    watchdog_enabled: bool = False
    watchdog_interval_minutes: int = 15
    watchdog_model: str = "claude-sonnet-4-6"
    watchdog_max_tokens_per_cycle: int = 1024
    watchdog_window_minutes: Optional[int] = None

    # Anthropic (Claude) API
    anthropic_api_key: Optional[str] = None


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

    # Environment variable overrides for sensitive settings
    # AGENTMON_SLACK_WEBHOOK takes precedence over config file
    env_slack_webhook = os.environ.get(ENV_SLACK_WEBHOOK)
    if env_slack_webhook:
        config.slack_webhook_url = env_slack_webhook
        # Auto-enable Slack if webhook is set via env var
        if not config.slack_enabled:
            logger.info(f"Slack enabled via {ENV_SLACK_WEBHOOK} environment variable")
            config.slack_enabled = True

    # AGENTMON_VIRUSTOTAL_API_KEY takes precedence over config file
    env_vt_key = os.environ.get(ENV_VIRUSTOTAL_API_KEY)
    if env_vt_key:
        config.virustotal_api_key = env_vt_key
        logger.info("VirusTotal API key loaded from environment variable")

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
                                block_all=rule_data.get("block_all", False),
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
                # Support both "policy" (string, legacy) and "policies" (list)
                policy_value = device_data.get("policies", device_data.get("policy", []))
                if isinstance(policy_value, str):
                    policy_names = [policy_value] if policy_value else []
                else:
                    policy_names = policy_value

                config.parental_devices.append(
                    Device(
                        name=device_data.get("name", "unknown"),
                        client_ips=device_data.get("client_ips", []),
                        policy_names=policy_names,
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

    # VirusTotal section
    if "virustotal" in data:
        vt = data["virustotal"]
        if "api_key" in vt:
            config.virustotal_api_key = vt["api_key"]

    # Threat Intelligence Feeds section
    if "threat_feeds" in data:
        tf = data["threat_feeds"]
        if "enabled" in tf:
            config.threat_feeds_enabled = tf["enabled"]
        if "cache_dir" in tf:
            config.threat_feeds_cache_dir = Path(tf["cache_dir"]).expanduser()
        if "update_interval_hours" in tf:
            config.threat_feeds_update_interval_hours = tf["update_interval_hours"]
        if "alert_severity" in tf:
            config.threat_feeds_severity = tf["alert_severity"]

    # Volume Anomaly Detection section
    if "volume_anomaly" in data:
        va = data["volume_anomaly"]
        if "enabled" in va:
            config.volume_anomaly_enabled = va["enabled"]
        if "learning_days" in va:
            config.volume_anomaly_learning_days = va["learning_days"]
        if "sensitivity_sigma" in va:
            config.volume_anomaly_sensitivity_sigma = va["sensitivity_sigma"]
        if "min_samples" in va:
            config.volume_anomaly_min_samples = va["min_samples"]
        if "min_query_threshold" in va:
            config.volume_anomaly_min_query_threshold = va["min_query_threshold"]
        if "min_domain_threshold" in va:
            config.volume_anomaly_min_domain_threshold = va["min_domain_threshold"]
        if "sustained_hours" in va:
            config.volume_anomaly_sustained_hours = va["sustained_hours"]
        if "spike_severity" in va:
            config.volume_anomaly_spike_severity = va["spike_severity"]
        if "diversity_severity" in va:
            config.volume_anomaly_diversity_severity = va["diversity_severity"]
        if "sustained_severity" in va:
            config.volume_anomaly_sustained_severity = va["sustained_severity"]

        # Parse named devices
        if "devices" in va:
            for device_data in va["devices"]:
                config.volume_anomaly_devices.append({
                    "name": device_data.get("name", "unknown"),
                    "client_ips": device_data.get("client_ips", []),
                })

    # OODA Watchdog section
    if "watchdog" in data:
        wd = data["watchdog"]
        if "enabled" in wd:
            config.watchdog_enabled = wd["enabled"]
        if "interval_minutes" in wd:
            config.watchdog_interval_minutes = wd["interval_minutes"]
        if "model" in wd:
            config.watchdog_model = wd["model"]
        if "max_tokens_per_cycle" in wd:
            config.watchdog_max_tokens_per_cycle = wd["max_tokens_per_cycle"]
        if "window_minutes" in wd:
            config.watchdog_window_minutes = wd["window_minutes"]

    # Dashboard section
    if "dashboard" in data:
        dash = data["dashboard"]
        if "host" in dash:
            config.dashboard_host = dash["host"]
        if "port" in dash:
            config.dashboard_port = dash["port"]

    # ANTHROPIC_API_KEY env var
    env_anthropic_key = os.environ.get(ENV_ANTHROPIC_API_KEY)
    if env_anthropic_key:
        config.anthropic_api_key = env_anthropic_key
        logger.info("Anthropic API key loaded from environment variable")

    return config


# Fields that are safe to hot-reload via SIGHUP without restarting.
_TUNABLE_FIELDS: set[str] = {
    "allowlist",
    "known_bad_patterns",
    "entropy_threshold",
    "entropy_min_length",
    "ignore_suffixes",
    "alert_dedup_window",
    "parental_devices",
    "parental_policies",
}

# Fields that require a restart to take effect.
_STRUCTURAL_FIELDS: set[str] = {
    "syslog_port",
    "syslog_bind_address",
    "syslog_protocol",
    "db_path",
    "llm_enabled",
    "llm_triage_model",
    "llm_escalation_model",
    "resolver_enabled",
    "device_activity_enabled",
    "volume_anomaly_enabled",
    "watchdog_enabled",
    "slack_enabled",
}


def reload_tunable_config(
    config_path: Path | None,
    current: Config,
) -> tuple[Config, list[str]]:
    """Re-read config file and return updated config with change descriptions.

    Compares tunable fields against the current config and returns the new
    config plus human-readable descriptions of what changed.  Non-tunable
    (structural) field changes produce "restart required" warnings.

    On parse failure, returns the current config unchanged with an error message.

    Args:
        config_path: Explicit path to config file, or None to search.
        current: The currently active Config instance.

    Returns:
        Tuple of (new Config, list of change descriptions).
    """
    try:
        new = load_config(config_path)
    except Exception as e:
        return current, [f"Failed to reload config: {e}"]

    changes: list[str] = []

    # Check tunable fields for changes
    for field_name in _TUNABLE_FIELDS:
        old_val = getattr(current, field_name)
        new_val = getattr(new, field_name)
        if old_val != new_val:
            changes.append(f"{field_name} updated")

    # Check structural fields — warn but don't apply
    for field_name in _STRUCTURAL_FIELDS:
        old_val = getattr(current, field_name)
        new_val = getattr(new, field_name)
        if old_val != new_val:
            changes.append(
                f"{field_name} changed ({old_val!r} -> {new_val!r}) — restart required"
            )

    return new, changes


def append_to_allowlist(domain: str, config_path: Optional[Path] = None) -> Path:
    """Append a domain to the allowlist in the TOML config file.

    Reads the existing config, adds the domain to [analyzer] allowlist,
    and writes back atomically via temp file + rename.

    Args:
        domain: Domain to add to the allowlist.
        config_path: Path to config file. If None, uses find_config_file().

    Returns:
        Path to the config file that was updated.

    Raises:
        FileNotFoundError: If no config file exists.
        RuntimeError: If tomli_w is not installed.
    """
    if config_path is None:
        config_path = find_config_file()
    if config_path is None:
        # Create default config path
        config_path = get_default_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_bytes(b"")

    try:
        import tomli_w
    except ImportError as e:
        raise RuntimeError(
            "tomli_w is required for allowlist persistence. "
            "Install with: pip install tomli-w"
        ) from e

    # Read existing config
    with open(config_path, "rb") as f:
        data = tomli.load(f) if config_path.stat().st_size > 0 else {}

    # Ensure [analyzer] section exists
    if "analyzer" not in data:
        data["analyzer"] = {}

    # Ensure allowlist exists as a list
    if "allowlist" not in data["analyzer"]:
        data["analyzer"]["allowlist"] = []

    # Add domain if not already present
    if domain not in data["analyzer"]["allowlist"]:
        data["analyzer"]["allowlist"].append(domain)

    # Atomic write: temp file + rename
    import tempfile
    temp_fd, temp_path = tempfile.mkstemp(
        dir=config_path.parent, suffix=".toml.tmp"
    )
    try:
        with os.fdopen(temp_fd, "wb") as f:
            tomli_w.dump(data, f)
        os.replace(temp_path, config_path)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise

    logger.info(f"Added '{domain}' to allowlist in {config_path}")
    return config_path


def update_tunable_field(
    field_name: str,
    value: str,
    config_path: Path | None = None,
) -> Path:
    """Update a tunable field in the TOML config file.

    Supported fields:
      - "add_allowlist": append domain to [analyzer] allowlist
      - "add_known_bad": append pattern to [analyzer] known_bad_patterns

    Args:
        field_name: The tunable field operation (e.g. "add_allowlist").
        value: The domain or pattern to add.
        config_path: Path to config file. If None, uses find_config_file().

    Returns:
        Path to the config file that was updated.

    Raises:
        FileNotFoundError: If no config file exists.
        RuntimeError: If tomli_w is not installed.
        ValueError: If field_name is not a supported tunable field.
    """
    if field_name == "add_allowlist":
        return append_to_allowlist(value, config_path)

    if field_name == "add_known_bad":
        if config_path is None:
            config_path = find_config_file()
        if config_path is None:
            config_path = get_default_config_path()
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_bytes(b"")

        try:
            import tomli_w
        except ImportError as e:
            raise RuntimeError(
                "tomli_w is required for config persistence. "
                "Install with: pip install tomli-w"
            ) from e

        with open(config_path, "rb") as f:
            data = tomli.load(f) if config_path.stat().st_size > 0 else {}

        if "analyzer" not in data:
            data["analyzer"] = {}
        if "known_bad_patterns" not in data["analyzer"]:
            data["analyzer"]["known_bad_patterns"] = []

        if value not in data["analyzer"]["known_bad_patterns"]:
            data["analyzer"]["known_bad_patterns"].append(value)

        import tempfile
        temp_fd, temp_path = tempfile.mkstemp(
            dir=config_path.parent, suffix=".toml.tmp"
        )
        try:
            with os.fdopen(temp_fd, "wb") as f:
                tomli_w.dump(data, f)
            os.replace(temp_path, config_path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

        logger.info(f"Added '{value}' to known_bad_patterns in {config_path}")
        return config_path

    raise ValueError(f"Unsupported tunable field: {field_name!r}")


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
