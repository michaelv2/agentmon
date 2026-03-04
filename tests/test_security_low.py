"""Tests for LOW priority security items from SECURITY.md.

Covers:
1. Per-IP rate limiting on syslog receiver
2. Paramiko RejectPolicy (instead of AutoAddPolicy)
3. Optional config file integrity check (SHA256 sidecar)
4. Configurable alert dedup cache size
5. Database file permissions (0o600)
"""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentmon.collectors.syslog_receiver import (
    SyslogConfig,
    TCPSyslogProtocol,
    UDPSyslogProtocol,
)

# ---------------------------------------------------------------------------
# 1. Syslog per-IP rate limiting
# ---------------------------------------------------------------------------


class TestSyslogRateLimiting:
    """Per-IP token bucket rate limiting for syslog receiver."""

    def test_udp_rate_limit_drops_excess(self) -> None:
        """UDP messages beyond rate limit should be silently dropped."""
        handler = MagicMock()
        config = SyslogConfig(
            protocol="udp",
            rate_limit_per_second=2,
        )
        protocol = UDPSyslogProtocol(handler, config)
        protocol.connection_made(MagicMock())

        msg = b"<30>Jan 26 14:32:15 host app: msg"
        # Send 5 messages quickly from same IP
        for _ in range(5):
            protocol.datagram_received(msg, ("192.168.1.100", 12345))

        # Only first 2 should be processed (rate_limit_per_second=2)
        assert handler.call_count == 2

    def test_udp_rate_limit_per_ip(self) -> None:
        """Rate limits should be tracked per source IP."""
        handler = MagicMock()
        config = SyslogConfig(
            protocol="udp",
            rate_limit_per_second=1,
        )
        protocol = UDPSyslogProtocol(handler, config)
        protocol.connection_made(MagicMock())

        msg = b"<30>Jan 26 14:32:15 host app: msg"
        # Send from two different IPs
        protocol.datagram_received(msg, ("192.168.1.100", 12345))
        protocol.datagram_received(msg, ("192.168.1.100", 12345))
        protocol.datagram_received(msg, ("192.168.1.200", 12345))
        protocol.datagram_received(msg, ("192.168.1.200", 12345))

        # 1 from each IP (rate limit = 1/sec)
        assert handler.call_count == 2

    def test_udp_no_rate_limit_when_zero(self) -> None:
        """When rate_limit_per_second=0 (default), no limiting is applied."""
        handler = MagicMock()
        config = SyslogConfig(protocol="udp", rate_limit_per_second=0)
        protocol = UDPSyslogProtocol(handler, config)
        protocol.connection_made(MagicMock())

        msg = b"<30>Jan 26 14:32:15 host app: msg"
        for _ in range(10):
            protocol.datagram_received(msg, ("192.168.1.100", 12345))

        assert handler.call_count == 10

    def test_tcp_rate_limit_drops_excess(self) -> None:
        """TCP messages beyond rate limit should be dropped."""
        handler = MagicMock()
        config = SyslogConfig(protocol="tcp", rate_limit_per_second=2)
        protocol = TCPSyslogProtocol(handler, config)

        transport = MagicMock()
        transport.get_extra_info.return_value = ("192.168.1.100", 12345)
        protocol.connection_made(transport)

        # Send 5 newline-delimited messages at once
        msgs = b"<30>Jan 26 14:32:15 host app: msg1\n" * 5
        protocol.data_received(msgs)

        assert handler.call_count == 2

    def test_syslog_config_rate_limit_default_zero(self) -> None:
        """SyslogConfig should default rate_limit_per_second to 0 (disabled)."""
        config = SyslogConfig()
        assert config.rate_limit_per_second == 0


# ---------------------------------------------------------------------------
# 2. Paramiko AutoAddPolicy → system known_hosts
# ---------------------------------------------------------------------------


class TestPiholeSSHHostKeyPolicy:
    """SSH collector should use system known_hosts, not AutoAddPolicy."""

    def test_uses_system_host_keys(self) -> None:
        """SSH client should load system host keys instead of AutoAddPolicy."""
        import importlib

        import paramiko as real_paramiko

        mock_paramiko = MagicMock()
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.RejectPolicy.return_value = "reject_policy"

        # Make exec_command return empty results
        mock_stdout = MagicMock()
        mock_stdout.__iter__ = lambda self: iter([])
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch.dict("sys.modules", {"paramiko": mock_paramiko}):
            # Re-import to get the patched paramiko
            import agentmon.collectors.pihole as pihole_mod
            importlib.reload(pihole_mod)

            config = pihole_mod.PiholeConfig(ssh_host="pihole.local", ssh_user="pi")
            collector = pihole_mod.PiholeCollector(config)

            import contextlib

            with contextlib.suppress(Exception):
                list(collector.collect_remote_ssh())

            # Should load system host keys
            mock_client.load_system_host_keys.assert_called_once()
            # Should set RejectPolicy, NOT AutoAddPolicy
            mock_client.set_missing_host_key_policy.assert_called_once_with(
                "reject_policy"
            )
            mock_paramiko.RejectPolicy.assert_called_once()

        # Restore original module
        import sys
        sys.modules["paramiko"] = real_paramiko
        importlib.reload(pihole_mod)


# ---------------------------------------------------------------------------
# 3. Optional SHA256 config file integrity check
# ---------------------------------------------------------------------------


class TestConfigIntegrityCheck:
    """Optional SHA256 checksum verification for config files."""

    def test_no_sidecar_loads_normally(self, tmp_path: Path) -> None:
        """Without a .sha256 sidecar, config loads normally."""
        from agentmon.config import load_config

        config_path = tmp_path / "agentmon.toml"
        config_path.write_text('[analyzer]\nentropy_threshold = 4.0\n')

        config = load_config(config_path)
        assert config.entropy_threshold == 4.0

    def test_valid_sidecar_passes(self, tmp_path: Path) -> None:
        """Config loads when .sha256 sidecar matches file content."""
        from agentmon.config import load_config

        config_path = tmp_path / "agentmon.toml"
        content = b'[analyzer]\nentropy_threshold = 4.0\n'
        config_path.write_bytes(content)

        sha256_hash = hashlib.sha256(content).hexdigest()
        sidecar = config_path.with_suffix(".toml.sha256")
        sidecar.write_text(sha256_hash)

        config = load_config(config_path)
        assert config.entropy_threshold == 4.0

    def test_invalid_sidecar_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Config loads with warning when .sha256 sidecar doesn't match."""
        import logging

        from agentmon.config import load_config

        config_path = tmp_path / "agentmon.toml"
        config_path.write_bytes(b'[analyzer]\nentropy_threshold = 4.0\n')

        sidecar = config_path.with_suffix(".toml.sha256")
        sidecar.write_text("0000000000000000000000000000000000000000000000000000000000000000")

        with caplog.at_level(logging.WARNING):
            config = load_config(config_path)

        # Should still load (warning, not error) but warn about mismatch
        assert config.entropy_threshold == 4.0
        assert any("integrity" in r.message.lower() or "checksum" in r.message.lower()
                    for r in caplog.records)


# ---------------------------------------------------------------------------
# 4. Configurable alert deduplication cache size
# ---------------------------------------------------------------------------


class TestConfigurableDedupCacheSize:
    """Alert dedup cache size should be configurable via config."""

    def test_config_has_dedup_cache_size_field(self) -> None:
        """Config dataclass should have alert_dedup_cache_size field."""
        from agentmon.config import Config

        config = Config()
        assert hasattr(config, "alert_dedup_cache_size")
        assert config.alert_dedup_cache_size == 5000  # default

    def test_load_config_reads_cache_size(self, tmp_path: Path) -> None:
        """load_config should read alert_dedup_cache_size from TOML."""
        from agentmon.config import load_config

        config_path = tmp_path / "agentmon.toml"
        config_path.write_text('[analyzer]\nalert_dedup_cache_size = 10000\n')

        config = load_config(config_path)
        assert config.alert_dedup_cache_size == 10000

    def test_analyzer_uses_configured_cache_size(self) -> None:
        """DNSBaselineAnalyzer should use configured cache size."""
        from agentmon.analyzers.dns_baseline import AnalyzerConfig, DNSBaselineAnalyzer

        analyzer_config = AnalyzerConfig()
        analyzer_config.alert_dedup_cache_size = 2000

        store = MagicMock()
        analyzer = DNSBaselineAnalyzer(store, config=analyzer_config)

        assert analyzer._alert_cache.maxsize == 2000

    def test_example_config_documents_setting(self) -> None:
        """Example config should document the alert_dedup_cache_size setting."""
        example_path = Path("/home/maqo/projects/agentmon/config/agentmon.example.toml")
        content = example_path.read_text()
        assert "alert_dedup_cache_size" in content


# ---------------------------------------------------------------------------
# 5. Database file permissions (0o600)
# ---------------------------------------------------------------------------


class TestDatabaseFilePermissions:
    """EventStore should set 0o600 permissions on database files."""

    def test_new_db_gets_secure_permissions(self, tmp_path: Path) -> None:
        """Newly created database file should have 0o600 permissions."""
        from agentmon.storage.db import EventStore

        db_path = tmp_path / "test_events.db"
        store = EventStore(db_path)
        store.connect()
        store.close()

        # File should have been created with restricted permissions
        mode = db_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_temp_copy_gets_secure_permissions(self, tmp_path: Path) -> None:
        """Temp DB copy for read-only access should have 0o600 permissions."""
        from agentmon.storage.db import EventStore

        db_path = tmp_path / "test_events.db"
        # Create a database first
        store = EventStore(db_path)
        store.connect()
        store.close()

        # Now simulate read-only with lock by patching duckdb.connect
        import duckdb

        original_connect = duckdb.connect

        call_count = 0

        def mock_connect(path: str, read_only: bool = False) -> duckdb.DuckDBPyConnection:
            nonlocal call_count
            call_count += 1
            if call_count == 1 and read_only:
                raise duckdb.IOException("Could not set lock")
            return original_connect(path, read_only=read_only)

        with patch("agentmon.storage.db.duckdb.connect", side_effect=mock_connect):
            ro_store = EventStore(db_path, read_only=True)
            ro_store.connect()

            if ro_store._temp_db_path and ro_store._temp_db_path.exists():
                mode = ro_store._temp_db_path.stat().st_mode & 0o777
                assert mode == 0o600, f"Temp DB expected 0o600, got {oct(mode)}"

            ro_store.close()
