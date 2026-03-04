"""Tests for MEDIUM priority security items from SECURITY.md.

Covers:
1. Database path traversal prevention (validate db_path against allowed dirs)
2. Known-bad pattern minimum length validation (reject < 2 chars)
3. IP validation for syslog allowed_ips (reject malformed IPs)
"""

import logging
from pathlib import Path

import pytest

from agentmon.config import Config, load_config

# ---------------------------------------------------------------------------
# 1. Database path traversal prevention
# ---------------------------------------------------------------------------


class TestDatabasePathTraversal:
    """Config loader should warn/reject db_path outside allowed directories."""

    def test_default_db_path_is_allowed(self) -> None:
        """Default db_path (~/.local/share/agentmon/events.db) should be accepted."""
        config = Config()
        # Default path should be under allowed dir
        resolved = config.db_path.expanduser().resolve()
        allowed_parent = Path.home() / ".local" / "share" / "agentmon"
        assert str(resolved).startswith(str(allowed_parent))

    def test_allowed_db_path_no_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A db_path under ~/.local/share/agentmon should load without warning."""
        config_path = tmp_path / "agentmon.toml"
        # Use the default (no [database] section) — should be allowed
        config_path.write_text("[analyzer]\nentropy_threshold = 3.5\n")

        with caplog.at_level(logging.WARNING):
            load_config(config_path)

        assert not any(
            "path traversal" in r.message.lower() or "outside allowed" in r.message.lower()
            for r in caplog.records
        )

    def test_disallowed_db_path_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A db_path outside allowed directories should log a warning."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[database]\npath = "/tmp/evil/events.db"\n'
        )

        with caplog.at_level(logging.WARNING):
            load_config(config_path)

        assert any(
            "outside allowed" in r.message.lower() or "path" in r.message.lower()
            for r in caplog.records
            if r.levelno >= logging.WARNING
        )

    def test_traversal_path_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A db_path with '..' traversal outside allowed dirs should warn."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[database]\npath = "~/.local/share/agentmon/../../etc/events.db"\n'
        )

        with caplog.at_level(logging.WARNING):
            load_config(config_path)

        assert any(
            "outside allowed" in r.message.lower() or "path" in r.message.lower()
            for r in caplog.records
            if r.levelno >= logging.WARNING
        )

    def test_var_lib_agentmon_is_allowed(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """/var/lib/agentmon/events.db should be an allowed path."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[database]\npath = "/var/lib/agentmon/events.db"\n'
        )

        with caplog.at_level(logging.WARNING):
            load_config(config_path)

        assert not any(
            "outside allowed" in r.message.lower()
            for r in caplog.records
        )

    def test_memory_db_is_allowed(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """:memory: should always be accepted."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text('[database]\npath = ":memory:"\n')

        with caplog.at_level(logging.WARNING):
            load_config(config_path)

        assert not any(
            "outside allowed" in r.message.lower()
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# 2. Known-bad pattern minimum length validation
# ---------------------------------------------------------------------------


class TestKnownBadPatternValidation:
    """Config loader should reject known_bad_patterns shorter than 2 chars."""

    def test_valid_patterns_preserved(self, tmp_path: Path) -> None:
        """Patterns with 2+ chars should be loaded normally."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[analyzer]\nknown_bad_patterns = ["c2-", "malware", "bot"]\n'
        )
        config = load_config(config_path)
        assert config.known_bad_patterns == ["c2-", "malware", "bot"]

    def test_empty_string_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Empty string pattern should be rejected with warning."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[analyzer]\nknown_bad_patterns = ["", "c2-", "malware"]\n'
        )

        with caplog.at_level(logging.WARNING):
            config = load_config(config_path)

        assert "" not in config.known_bad_patterns
        assert "c2-" in config.known_bad_patterns
        assert "malware" in config.known_bad_patterns

    def test_single_char_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Single-character patterns should be rejected with warning."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[analyzer]\nknown_bad_patterns = ["a", "c2-"]\n'
        )

        with caplog.at_level(logging.WARNING):
            config = load_config(config_path)

        assert "a" not in config.known_bad_patterns
        assert "c2-" in config.known_bad_patterns
        assert any(
            "too short" in r.message.lower() or "pattern" in r.message.lower()
            for r in caplog.records
            if r.levelno >= logging.WARNING
        )

    def test_all_short_patterns_rejected(self, tmp_path: Path) -> None:
        """If all patterns are too short, result should be empty list."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[analyzer]\nknown_bad_patterns = ["", "x"]\n'
        )
        config = load_config(config_path)
        assert config.known_bad_patterns == []


# ---------------------------------------------------------------------------
# 3. IP validation for syslog allowed_ips
# ---------------------------------------------------------------------------


class TestAllowedIPsValidation:
    """Config loader should validate allowed_ips are valid IP addresses."""

    def test_valid_ipv4_accepted(self, tmp_path: Path) -> None:
        """Valid IPv4 addresses should be loaded normally."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[syslog]\nallowed_ips = ["192.168.1.2", "10.0.0.1"]\n'
        )
        config = load_config(config_path)
        assert config.syslog_allowed_ips == ["192.168.1.2", "10.0.0.1"]

    def test_valid_ipv6_accepted(self, tmp_path: Path) -> None:
        """Valid IPv6 addresses should be loaded normally."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[syslog]\nallowed_ips = ["::1", "fe80::1"]\n'
        )
        config = load_config(config_path)
        assert config.syslog_allowed_ips == ["::1", "fe80::1"]

    def test_invalid_ip_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid IP addresses should be rejected with error log."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[syslog]\nallowed_ips = ["192.168.1.2", "not-an-ip", "10.0.0.1"]\n'
        )

        with caplog.at_level(logging.ERROR):
            config = load_config(config_path)

        assert "192.168.1.2" in config.syslog_allowed_ips
        assert "10.0.0.1" in config.syslog_allowed_ips
        assert "not-an-ip" not in config.syslog_allowed_ips
        assert any(
            "invalid" in r.message.lower() and "not-an-ip" in r.message
            for r in caplog.records
        )

    def test_typo_ip_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Typos like '192.168.1.999' should be rejected."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text(
            '[syslog]\nallowed_ips = ["192.168.1.999"]\n'
        )

        with caplog.at_level(logging.ERROR):
            config = load_config(config_path)

        assert config.syslog_allowed_ips == []

    def test_empty_allowlist_stays_empty(self, tmp_path: Path) -> None:
        """Empty allowed_ips should remain empty (no validation needed)."""
        config_path = tmp_path / "agentmon.toml"
        config_path.write_text("[syslog]\nallowed_ips = []\n")
        config = load_config(config_path)
        assert config.syslog_allowed_ips == []
