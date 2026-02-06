"""Integration tests for the syslog-to-alert pipeline.

End-to-end tests that wire up real components (SyslogReceiver, EventStore,
DNSBaselineAnalyzer) with a temp DuckDB and random port. No mocks for core
components — only external services (LLM, VT) are absent.
"""

import asyncio
import socket
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest

from agentmon.analyzers.dns_baseline import AnalyzerConfig, DNSBaselineAnalyzer
from agentmon.collectors.syslog_parsers import route_message
from agentmon.collectors.syslog_receiver import SyslogConfig, SyslogMessage, SyslogReceiver
from agentmon.storage.db import EventStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Find a free TCP/UDP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_syslog_line(
    domain: str,
    client: str = "192.168.1.100",
    query_type: str = "A",
    hostname: str = "pihole",
) -> bytes:
    """Build a raw RFC 3164 syslog line for a dnsmasq query."""
    now = datetime.now()
    ts = now.strftime("%b %d %H:%M:%S")
    # <30> = facility=daemon(3), severity=info(6) -> 3*8+6 = 30
    msg = f"<30>{ts} {hostname} dnsmasq[1234]: query[{query_type}] {domain} from {client}\n"
    return msg.encode()


def make_block_line(domain: str, hostname: str = "pihole") -> bytes:
    """Build a raw RFC 3164 syslog line for a gravity block notification."""
    now = datetime.now()
    ts = now.strftime("%b %d %H:%M:%S")
    return f"<30>{ts} {hostname} dnsmasq[1234]: gravity blocked {domain} is 0.0.0.0\n".encode()


async def send_tcp(port: int, data: bytes) -> None:
    """Send data over TCP to localhost:port."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def send_udp(port: int, data: bytes) -> None:
    """Send data over UDP to localhost:port."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=("127.0.0.1", port),
    )
    transport.sendto(data)
    # Small delay to ensure delivery before transport close
    await asyncio.sleep(0.05)
    transport.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Path:
    """Provide a temporary DuckDB path."""
    return tmp_path / "test_events.db"


@pytest.fixture()
def event_store(tmp_db_path: Path) -> EventStore:
    """Provide a connected EventStore on a temp DB."""
    store = EventStore(tmp_db_path)
    store.connect()
    yield store  # type: ignore[misc]
    store.close()


@pytest.fixture()
def analyzer_config() -> AnalyzerConfig:
    """Provide an AnalyzerConfig with known-bad patterns for testing."""
    return AnalyzerConfig(
        known_bad_patterns=["c2-", "malware", "botnet"],
        allowlist={"safe.example.com"},
        learning_mode=False,
    )


@pytest.fixture()
def analyzer(event_store: EventStore, analyzer_config: AnalyzerConfig) -> DNSBaselineAnalyzer:
    """Provide a DNSBaselineAnalyzer wired to the test EventStore."""
    return DNSBaselineAnalyzer(event_store, analyzer_config)


# ---------------------------------------------------------------------------
# Pipeline helper — mirrors cli.py handle_message() logic
# ---------------------------------------------------------------------------


def _make_handle_message(
    store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> Callable[[SyslogMessage], None]:
    """Create a handle_message callback that runs the full pipeline."""

    def handle_message(msg: SyslogMessage) -> None:
        dns_event, _conn_event = route_message(msg)
        if dns_event is None:
            return

        # Block notifications: correlate with recent query
        if dns_event.client == "__BLOCK_NOTIFICATION__":
            store.mark_domain_blocked(dns_event.domain)
            return

        store.insert_dns_event(dns_event)
        alerts = analyzer.analyze_event(dns_event)
        for alert in alerts:
            store.insert_alert(alert)

    return handle_message


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcp_syslog_to_stored_event(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Send syslog over TCP -> DNSEvent appears in DuckDB."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    try:
        await send_tcp(port, make_syslog_line("example.com"))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    rows = event_store.conn.execute(
        "SELECT domain, client FROM dns_events"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "example.com"
    assert rows[0][1] == "192.168.1.100"


@pytest.mark.asyncio
async def test_udp_syslog_to_stored_event(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Send syslog over UDP -> DNSEvent appears in DuckDB."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="udp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    try:
        await send_udp(port, make_syslog_line("udp-test.example.com"))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    rows = event_store.conn.execute(
        "SELECT domain FROM dns_events"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "udp-test.example.com"


@pytest.mark.asyncio
async def test_known_bad_generates_alert(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Syslog for a known-bad domain -> HIGH alert in DB."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    try:
        await send_tcp(port, make_syslog_line("c2-server.evil.com"))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    alerts = event_store.conn.execute(
        "SELECT severity, title, domain FROM alerts"
    ).fetchall()
    assert len(alerts) >= 1
    # At least one HIGH alert for the known-bad pattern
    high_alerts = [a for a in alerts if a[0] == "high"]
    assert len(high_alerts) >= 1
    assert "c2-server.evil.com" in high_alerts[0][2]


@pytest.mark.asyncio
async def test_dga_domain_generates_alert(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Syslog for a DGA-like domain -> alert in DB."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    # This domain triggers multiple DGA signals:
    # - high entropy, long alphanumeric sequence, unusual consonant ratio
    dga_domain = "xjf8dk2jdksla9dkj3qwp7nm.evil.com"

    await receiver.start()
    try:
        await send_tcp(port, make_syslog_line(dga_domain))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    alerts = event_store.conn.execute(
        "SELECT severity, title, analyzer FROM alerts"
    ).fetchall()
    # Should have at least one DGA or entropy alert
    dga_alerts = [a for a in alerts if "dga" in a[2] or "entropy" in a[2]]
    assert len(dga_alerts) >= 1


@pytest.mark.asyncio
async def test_learning_mode_no_new_domain_alerts(
    event_store: EventStore,
) -> None:
    """Learning mode: baseline updated, no 'new domain' alerts generated.

    Note: known-bad and DGA alerts still fire in learning mode by design
    (security-critical detections should never be suppressed). Learning
    mode only suppresses the low-severity 'new domain observed' alerts.
    """
    learning_config = AnalyzerConfig(
        known_bad_patterns=[],  # No patterns to avoid known-bad alerts
        learning_mode=True,
    )
    learning_analyzer = DNSBaselineAnalyzer(event_store, learning_config)

    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, learning_analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    try:
        # A normal new domain should NOT generate alerts in learning mode
        await send_tcp(port, make_syslog_line("new-domain.example.com"))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    # Baseline should be updated
    baseline = event_store.conn.execute(
        "SELECT COUNT(*) FROM domain_baseline"
    ).fetchone()
    assert baseline[0] >= 1

    # No "new domain" alerts should be generated
    alert_count = event_store.conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()
    assert alert_count[0] == 0


@pytest.mark.asyncio
async def test_allowlist_bypasses_alert(
    event_store: EventStore,
) -> None:
    """Allowlisted domain produces no alert even if it matches known-bad."""
    allowlist_config = AnalyzerConfig(
        known_bad_patterns=["safe"],
        allowlist={"safe.example.com"},
        learning_mode=False,
    )
    allowlist_analyzer = DNSBaselineAnalyzer(event_store, allowlist_config)

    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, allowlist_analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    try:
        await send_tcp(port, make_syslog_line("safe.example.com"))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    alerts = event_store.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    assert alerts[0] == 0


@pytest.mark.asyncio
async def test_baseline_update_on_new_domain(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """First query for a domain updates domain_baseline table."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    domain = "brand-new-domain.example.com"

    # Verify baseline is empty initially
    count = event_store.conn.execute(
        "SELECT COUNT(*) FROM domain_baseline WHERE domain = ?",
        [domain],
    ).fetchone()
    assert count[0] == 0

    await receiver.start()
    try:
        await send_tcp(port, make_syslog_line(domain))
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    # Baseline should now contain this domain
    row = event_store.conn.execute(
        "SELECT client, domain, query_count FROM domain_baseline WHERE domain = ?",
        [domain],
    ).fetchone()
    assert row is not None
    assert row[0] == "192.168.1.100"
    assert row[1] == domain
    assert row[2] == 1


@pytest.mark.asyncio
async def test_block_correlation(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Query + block notification -> blocked=True on stored event."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    domain = "ads.tracker.com"

    await receiver.start()
    try:
        # Send query first, then block notification
        data = make_syslog_line(domain) + make_block_line(domain)
        await send_tcp(port, data)
        await asyncio.sleep(0.3)
    finally:
        await receiver.stop()

    rows = event_store.conn.execute(
        "SELECT domain, blocked FROM dns_events WHERE domain = ?",
        [domain],
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][1] is True  # blocked should be updated to True


@pytest.mark.asyncio
async def test_receiver_graceful_shutdown(
    event_store: EventStore,
    analyzer: DNSBaselineAnalyzer,
) -> None:
    """Start receiver, send message, stop -> data persisted, is_running=False."""
    port = _free_port()
    config = SyslogConfig(port=port, protocol="tcp", bind_address="127.0.0.1")
    handler = _make_handle_message(event_store, analyzer)
    receiver = SyslogReceiver(config, handler)

    await receiver.start()
    assert receiver.is_running is True

    await send_tcp(port, make_syslog_line("shutdown-test.example.com"))
    await asyncio.sleep(0.2)

    await receiver.stop()
    assert receiver.is_running is False

    # Data should be persisted
    count = event_store.conn.execute(
        "SELECT COUNT(*) FROM dns_events WHERE domain = 'shutdown-test.example.com'"
    ).fetchone()
    assert count[0] == 1
