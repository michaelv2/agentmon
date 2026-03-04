"""Tests for Phase 2: OpenWRT Connection Event Pipeline.

Covers storage, DNS-to-connection correlation, and direct IP access detection.
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from agentmon.models import Alert, ConnectionEvent, DNSEvent, Severity
from agentmon.storage import EventStore


# ── Helpers ────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _conn(
    client: str = "192.168.1.100",
    dst_ip: str = "93.184.216.34",
    dst_port: int = 443,
    protocol: str = "tcp",
    dns_domain: str | None = None,
    ts: datetime | None = None,
) -> ConnectionEvent:
    return ConnectionEvent(
        timestamp=ts or _now(),
        client=client,
        src_port=45678,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        dns_domain=dns_domain,
    )


def _dns(
    client: str = "192.168.1.100",
    domain: str = "example.com",
    ts: datetime | None = None,
) -> DNSEvent:
    return DNSEvent(
        timestamp=ts or _now(),
        client=client,
        domain=domain,
        query_type="A",
        blocked=False,
    )


@pytest.fixture()
def store() -> EventStore:
    s = EventStore(Path(":memory:"))
    s.connect()
    yield s  # type: ignore[misc]
    s.close()


# ── TestInsertConnectionEvent ──────────────────────────────────────────────

class TestInsertConnectionEvent:
    """Storage layer for connection events."""

    def test_insert_connection_event(self, store: EventStore) -> None:
        event = _conn(dns_domain="example.com")
        event_id = store.insert_connection_event(event)

        assert event_id  # non-empty UUID string
        row = store.conn.execute(
            "SELECT * FROM connection_events WHERE id = ?", [event_id]
        ).fetchone()
        assert row is not None
        cols = [d[0] for d in store.conn.description]
        data = dict(zip(cols, row))
        assert data["client"] == "192.168.1.100"
        assert data["dst_ip"] == "93.184.216.34"
        assert data["dst_port"] == 443
        assert data["protocol"] == "tcp"
        assert data["dns_domain"] == "example.com"

    def test_insert_connection_events_batch(self, store: EventStore) -> None:
        events = [_conn(dst_ip=f"10.0.0.{i}") for i in range(5)]
        count = store.insert_connection_events_batch(events)

        assert count == 5
        total = store.conn.execute("SELECT COUNT(*) FROM connection_events").fetchone()
        assert total[0] == 5

    def test_insert_connection_events_batch_empty(self, store: EventStore) -> None:
        count = store.insert_connection_events_batch([])
        assert count == 0

    def test_cleanup_deletes_old_connection_events(self, store: EventStore) -> None:
        old_ts = _now() - timedelta(days=10)
        new_ts = _now()

        store.insert_connection_event(_conn(ts=old_ts, dst_ip="1.1.1.1"))
        store.insert_connection_event(_conn(ts=new_ts, dst_ip="2.2.2.2"))

        result = store.cleanup_old_data(
            dns_events_days=30,
            alerts_days=90,
            connection_events_days=5,
        )

        assert result["connection_events_deleted"] == 1
        remaining = store.conn.execute("SELECT COUNT(*) FROM connection_events").fetchone()
        assert remaining[0] == 1

    def test_get_table_stats_includes_connection_events(self, store: EventStore) -> None:
        store.insert_connection_event(_conn())
        stats = store.get_table_stats()

        assert "connection_events" in stats
        assert stats["connection_events"]["count"] == 1
        assert stats["connection_events"]["oldest"] is not None
        assert stats["connection_events"]["newest"] is not None


# ── TestDNSCorrelation ─────────────────────────────────────────────────────

class TestDNSCorrelation:
    """Correlating connections to recent DNS answers."""

    def test_correlate_finds_matching_dns(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        # DNS query happens first
        dns_event = _dns(domain="example.com")
        analyzer.track_dns_answer(dns_event)

        # Connection follows — mock reverse DNS to return matching domain
        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value="example.com"):
            updated, _ = analyzer.analyze_event(conn)

        assert updated.dns_domain == "example.com"

    def test_correlate_no_match_returns_none(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        # No DNS query tracked
        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value="other.com"):
            updated, _ = analyzer.analyze_event(conn)

        assert updated.dns_domain is None

    def test_correlate_respects_time_window(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        config = ConnectionAnalyzerConfig(dns_cache_ttl=60)
        analyzer = ConnectionAnalyzer(store, config)

        # DNS event from 2 minutes ago (expired from 60s TTL cache)
        old_ts = _now() - timedelta(seconds=120)
        dns_event = _dns(domain="example.com", ts=old_ts)
        analyzer.track_dns_answer(dns_event)

        # TTL cache should have expired; force it by clearing
        analyzer._dns_domains.clear()

        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value="example.com"):
            updated, _ = analyzer.analyze_event(conn)

        assert updated.dns_domain is None

    def test_correlate_uses_same_client(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        # DNS from client A
        analyzer.track_dns_answer(_dns(client="192.168.1.50", domain="example.com"))

        # Connection from client B
        conn = _conn(client="192.168.1.99", dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value="example.com"):
            updated, _ = analyzer.analyze_event(conn)

        assert updated.dns_domain is None


# ── TestDirectIPAccessAnalyzer ─────────────────────────────────────────────

class TestDirectIPAccessAnalyzer:
    """Direct IP access detection."""

    def test_direct_ip_alerts_when_no_dns(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value=None):
            _, alerts = analyzer.analyze_event(conn)

        assert len(alerts) == 1
        assert alerts[0].severity == Severity.MEDIUM
        assert alerts[0].analyzer == "connection.direct_ip"

    def test_no_alert_when_dns_exists(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())
        analyzer.track_dns_answer(_dns(domain="example.com"))

        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value="example.com"):
            _, alerts = analyzer.analyze_event(conn)

        assert len(alerts) == 0

    def test_no_alert_in_learning_mode(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        config = ConnectionAnalyzerConfig(learning_mode=True)
        analyzer = ConnectionAnalyzer(store, config)

        conn = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value=None):
            _, alerts = analyzer.analyze_event(conn)

        assert len(alerts) == 0

    def test_no_alert_for_private_ips(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        private_ips = [
            "10.0.0.1",         # RFC1918 Class A
            "172.16.5.1",       # RFC1918 Class B
            "192.168.1.1",      # RFC1918 Class C
            "127.0.0.1",        # Loopback
            "169.254.1.1",      # Link-local
        ]
        for ip in private_ips:
            conn = _conn(dst_ip=ip)
            with patch("agentmon.analyzers.connection.reverse_lookup", return_value=None):
                _, alerts = analyzer.analyze_event(conn)
            assert len(alerts) == 0, f"Private IP {ip} should not generate alert"

    def test_alert_deduplication(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        conn1 = _conn(dst_ip="93.184.216.34")
        conn2 = _conn(dst_ip="93.184.216.34")
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value=None):
            _, alerts1 = analyzer.analyze_event(conn1)
            _, alerts2 = analyzer.analyze_event(conn2)

        assert len(alerts1) == 1
        assert len(alerts2) == 0  # Deduplicated

    def test_alert_fields(self, store: EventStore) -> None:
        from agentmon.analyzers.connection import ConnectionAnalyzer, ConnectionAnalyzerConfig

        analyzer = ConnectionAnalyzer(store, ConnectionAnalyzerConfig())

        conn = _conn(client="192.168.1.100", dst_ip="93.184.216.34", dst_port=443)
        with patch("agentmon.analyzers.connection.reverse_lookup", return_value=None):
            _, alerts = analyzer.analyze_event(conn)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.source_event_type == "connection"
        assert alert.client == "192.168.1.100"
        assert alert.dst_ip == "93.184.216.34"
        assert alert.analyzer == "connection.direct_ip"
        assert 0.0 <= alert.confidence <= 1.0
