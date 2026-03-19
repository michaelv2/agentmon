"""Tests for the Sonnet assessment recommendations:

1. Query frequency threshold — suppress DGA on popular domains
2. Trusted infrastructure modifier — CDN/cloud parents suppress entropy alerts
3. Alert deduplication — 1-hour cooldown
4. OCSP spike detection — volume anomaly for certificate validation domains
5. Watched domains — enhanced monitoring for C2 fronting / exfil blind spots
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentmon.analyzers.dns_baseline import (
    AnalyzerConfig,
    DEFAULT_DEDUP_WINDOW,
    DNSBaselineAnalyzer,
)
from agentmon.analyzers.entropy import (
    DEFAULT_TRUSTED_INFRASTRUCTURE,
    get_parent_domain,
    is_trusted_infrastructure,
)
from agentmon.models import DNSEvent
from agentmon.storage.db import EventStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _event(
    domain: str = "example.com",
    client: str = "192.168.1.100",
    timestamp: datetime | None = None,
) -> DNSEvent:
    return DNSEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        client=client,
        domain=domain,
        query_type="A",
        blocked=False,
    )


@pytest.fixture()
def store() -> EventStore:
    s = EventStore(Path(":memory:"))
    s.connect()
    return s


# ---------------------------------------------------------------------------
# 1. Trusted Infrastructure Modifier
# ---------------------------------------------------------------------------

class TestTrustedInfrastructure:
    """High entropy under CDN/cloud parents should NOT trigger DGA alerts."""

    def test_get_parent_domain(self) -> None:
        assert get_parent_domain("e1234.dscd.akamaiedge.net") == "akamaiedge.net"
        assert get_parent_domain("ocsp2.g.aaplimg.com") == "aaplimg.com"
        assert get_parent_domain("example.com") == "example.com"
        assert get_parent_domain("a.b.c.d.cloudfront.net") == "cloudfront.net"

    def test_get_parent_domain_single_label(self) -> None:
        assert get_parent_domain("localhost") == "localhost"

    def test_is_trusted_infrastructure_defaults(self) -> None:
        assert is_trusted_infrastructure("e1234.dscd.akamaiedge.net")
        assert is_trusted_infrastructure("ocsp2.g.aaplimg.com")
        assert is_trusted_infrastructure("d1234.cloudfront.net")
        assert not is_trusted_infrastructure("evil-dga-domain.com")

    def test_is_trusted_infrastructure_custom(self) -> None:
        custom = frozenset({"mycdn.net"})
        assert is_trusted_infrastructure("random.mycdn.net", custom)
        assert not is_trusted_infrastructure("random.akamaiedge.net", custom)

    def test_default_set_includes_major_providers(self) -> None:
        for parent in ["akadns.net", "aaplimg.com", "apple.com",
                        "cloudfront.net", "amazonaws.com"]:
            assert parent in DEFAULT_TRUSTED_INFRASTRUCTURE

    def test_dga_suppressed_for_akamai(self, store: EventStore) -> None:
        """DGA-looking domain under akamaiedge.net should not alert."""
        config = AnalyzerConfig(known_bad_patterns=[])
        analyzer = DNSBaselineAnalyzer(store, config)

        # This would normally trigger DGA detection (high entropy, long random)
        event = _event("e7593.dscd.akamaiedge.net")
        alerts = analyzer.analyze_event(event)

        dga_alerts = [a for a in alerts if a.analyzer == "dns_baseline.dga"]
        entropy_alerts = [a for a in alerts if a.analyzer == "dns_baseline.entropy"]
        assert len(dga_alerts) == 0
        assert len(entropy_alerts) == 0

    def test_dga_still_fires_for_unknown_tld(self, store: EventStore) -> None:
        """DGA-looking domain under unknown parent should still alert."""
        config = AnalyzerConfig(known_bad_patterns=[])
        analyzer = DNSBaselineAnalyzer(store, config)

        # Obvious DGA: high entropy + long alphanumeric
        event = _event("a8k3m9d7f2x1z5q4w8.evil.com")
        alerts = analyzer.analyze_event(event)

        dga_alerts = [a for a in alerts if a.analyzer == "dns_baseline.dga"]
        assert len(dga_alerts) == 1

    def test_trusted_infra_does_not_bypass_threat_feeds(self, store: EventStore) -> None:
        """Trusted infrastructure should still check threat feeds."""
        from unittest.mock import MagicMock

        feed_mgr = MagicMock()
        feed_mgr.check_domain.return_value = {"source": "urlhaus"}

        config = AnalyzerConfig(known_bad_patterns=[])
        analyzer = DNSBaselineAnalyzer(store, config, threat_feed_manager=feed_mgr)

        event = _event("malware.akamaiedge.net")
        alerts = analyzer.analyze_event(event)

        threat_alerts = [a for a in alerts if a.analyzer == "dns_baseline.threat_feed"]
        assert len(threat_alerts) == 1


# ---------------------------------------------------------------------------
# 2. Query Frequency Threshold
# ---------------------------------------------------------------------------

class TestQueryFrequencyThreshold:
    """Domains queried >N times from >M clients suppress DGA alerts."""

    def test_popular_domain_suppresses_dga(self, store: EventStore) -> None:
        """A domain queried by many clients should not trigger DGA."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            dga_min_queries_suppress=10,
            dga_min_clients_suppress=3,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        # Pre-populate baseline: 4 clients each queried this domain
        dga_domain = "a8k3m9d7f2x1z5q4w8.notcdn.com"
        now = datetime.now(timezone.utc)
        for i in range(4):
            client = f"192.168.1.{10 + i}"
            for _ in range(5):
                store.update_domain_baseline(client, dga_domain, now)

        # Now analyze the domain — should be suppressed
        event = _event(dga_domain)
        alerts = analyzer.analyze_event(event)

        dga_alerts = [a for a in alerts if a.analyzer == "dns_baseline.dga"]
        assert len(dga_alerts) == 0

    def test_unpopular_domain_still_alerts(self, store: EventStore) -> None:
        """A domain queried by few clients should still trigger DGA."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            dga_min_queries_suppress=50,
            dga_min_clients_suppress=5,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        # Only 1 client, 2 queries — well below thresholds
        dga_domain = "a8k3m9d7f2x1z5q4w8.notcdn.com"
        now = datetime.now(timezone.utc)
        store.update_domain_baseline("192.168.1.10", dga_domain, now)
        store.update_domain_baseline("192.168.1.10", dga_domain, now)

        event = _event(dga_domain)
        alerts = analyzer.analyze_event(event)

        dga_alerts = [a for a in alerts if a.analyzer == "dns_baseline.dga"]
        assert len(dga_alerts) == 1

    def test_high_queries_low_clients_still_alerts(self, store: EventStore) -> None:
        """Many queries from one client should still alert (not enough diversity)."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            dga_min_queries_suppress=10,
            dga_min_clients_suppress=3,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        dga_domain = "a8k3m9d7f2x1z5q4w8.notcdn.com"
        now = datetime.now(timezone.utc)
        for _ in range(20):
            store.update_domain_baseline("192.168.1.10", dga_domain, now)

        event = _event(dga_domain)
        alerts = analyzer.analyze_event(event)

        dga_alerts = [a for a in alerts if a.analyzer == "dns_baseline.dga"]
        assert len(dga_alerts) == 1

    def test_get_domain_popularity(self, store: EventStore) -> None:
        """EventStore.get_domain_popularity returns correct counts."""
        now = datetime.now(timezone.utc)
        store.update_domain_baseline("client-a", "test.com", now)
        store.update_domain_baseline("client-a", "test.com", now)
        store.update_domain_baseline("client-b", "test.com", now)
        store.update_domain_baseline("client-c", "other.com", now)

        total_queries, unique_clients = store.get_domain_popularity("test.com")
        assert total_queries == 3
        assert unique_clients == 2

        # Unknown domain
        total_queries, unique_clients = store.get_domain_popularity("unknown.com")
        assert total_queries == 0
        assert unique_clients == 0


# ---------------------------------------------------------------------------
# 3. Alert Deduplication — 1-Hour Cooldown
# ---------------------------------------------------------------------------

class TestAlertDeduplication:
    """Default dedup window should be 1 hour (3600s)."""

    def test_default_dedup_window_is_one_hour(self) -> None:
        assert DEFAULT_DEDUP_WINDOW == 3600

    def test_config_default_is_one_hour(self) -> None:
        config = AnalyzerConfig()
        assert config.alert_dedup_window == 3600

    def test_dedup_suppresses_repeat_alert(self, store: EventStore) -> None:
        """Same (domain, client, type) within window should be suppressed."""
        config = AnalyzerConfig(
            known_bad_patterns=["malware"],
            alert_dedup_window=3600,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        event = _event("malware.evil.com")
        first_alerts = analyzer.analyze_event(event)
        second_alerts = analyzer.analyze_event(event)

        assert len(first_alerts) >= 1
        # Second call should be suppressed by dedup
        known_bad_second = [
            a for a in second_alerts if a.analyzer == "dns_baseline.known_bad"
        ]
        assert len(known_bad_second) == 0

    def test_dedup_stats_tracked(self, store: EventStore) -> None:
        """Dedup hits should be reflected in stats."""
        config = AnalyzerConfig(known_bad_patterns=["malware"])
        analyzer = DNSBaselineAnalyzer(store, config)

        event = _event("malware.evil.com")
        analyzer.analyze_event(event)
        analyzer.analyze_event(event)

        stats = analyzer.dedup_stats
        assert stats["suppressed"] >= 1


# ---------------------------------------------------------------------------
# 4. OCSP Spike Detection
# ---------------------------------------------------------------------------

class TestOCSPSpikeDetection:
    """Detect sudden spikes in OCSP queries from a single client."""

    def test_ocsp_spike_fires_at_threshold(self, store: EventStore) -> None:
        """Should alert when client hits OCSP query threshold."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=True,
            ocsp_spike_threshold=5,  # Low threshold for testing
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        ocsp_alerts = []
        for i in range(6):
            event = _event("ocsp2.apple.com", timestamp=now)
            alerts = analyzer.analyze_event(event)
            ocsp_alerts.extend(
                a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
            )

        # Should fire exactly once (at threshold=5)
        assert len(ocsp_alerts) == 1
        assert "OCSP query spike" in ocsp_alerts[0].title
        assert "certificate pinning" in ocsp_alerts[0].description

    def test_ocsp_spike_not_fired_below_threshold(self, store: EventStore) -> None:
        """Should not alert below threshold."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=True,
            ocsp_spike_threshold=100,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        for _ in range(10):
            event = _event("ocsp2.apple.com", timestamp=now)
            alerts = analyzer.analyze_event(event)
            ocsp_alerts = [
                a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
            ]
            assert len(ocsp_alerts) == 0

    def test_ocsp_spike_ignores_non_ocsp(self, store: EventStore) -> None:
        """Non-OCSP domains should never trigger OCSP spike."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=True,
            ocsp_spike_threshold=2,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        for _ in range(5):
            event = _event("api.example.com", timestamp=now)
            alerts = analyzer.analyze_event(event)
            ocsp_alerts = [
                a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
            ]
            assert len(ocsp_alerts) == 0

    def test_ocsp_spike_per_client_isolation(self, store: EventStore) -> None:
        """Different clients should have separate OCSP counters."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=True,
            ocsp_spike_threshold=3,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        # 2 queries from each of 2 clients — neither hits threshold of 3
        for client in ["192.168.1.10", "192.168.1.20"]:
            for _ in range(2):
                event = _event("ocsp.digicert.com", client=client, timestamp=now)
                alerts = analyzer.analyze_event(event)
                ocsp_alerts = [
                    a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
                ]
                assert len(ocsp_alerts) == 0

    def test_ocsp_spike_disabled(self, store: EventStore) -> None:
        """Should not fire when ocsp_spike_enabled is False."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=False,
            ocsp_spike_threshold=1,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        for _ in range(5):
            event = _event("ocsp2.apple.com", timestamp=now)
            alerts = analyzer.analyze_event(event)
            ocsp_alerts = [
                a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
            ]
            assert len(ocsp_alerts) == 0

    def test_ocsp_spike_hour_boundary_resets(self, store: EventStore) -> None:
        """Counters should reset when the hour changes."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            ocsp_spike_enabled=True,
            ocsp_spike_threshold=3,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        # 2 queries at hour 10
        hour10 = datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc)
        for _ in range(2):
            event = _event("ocsp2.apple.com", timestamp=hour10)
            analyzer.analyze_event(event)

        # Switch to hour 11 — counter should reset
        hour11 = datetime(2024, 1, 1, 11, 5, tzinfo=timezone.utc)
        ocsp_alerts = []
        for _ in range(4):
            event = _event("ocsp2.apple.com", timestamp=hour11)
            alerts = analyzer.analyze_event(event)
            ocsp_alerts.extend(
                a for a in alerts if a.analyzer == "dns_baseline.ocsp_spike"
            )

        # Should fire at count=3 within hour 11 (not carry over from hour 10)
        assert len(ocsp_alerts) == 1


# ---------------------------------------------------------------------------
# 5. Watched Domains — C2 Fronting / Exfil Blind Spot Monitoring
# ---------------------------------------------------------------------------

class TestWatchedDomains:
    """Enhanced monitoring for domains that could be abused as C2/exfil vectors."""

    def test_first_query_generates_alert(self, store: EventStore) -> None:
        """First query to a watched domain from a new client should alert."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["*.doubleclick.net"],
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        event = _event("static.doubleclick.net")
        alerts = analyzer.analyze_event(event)

        watched = [a for a in alerts if a.analyzer == "dns_baseline.watched_domain"]
        assert len(watched) == 1
        assert "first time" in watched[0].description
        assert watched[0].severity.value == "low"
        assert "watched" in watched[0].tags

    def test_second_query_no_first_alert(self, store: EventStore) -> None:
        """After baseline is established, no more first-query alerts."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["clients4.google.com"],
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        # First query → alert
        event = _event("clients4.google.com", timestamp=now)
        first_alerts = analyzer.analyze_event(event)
        first_watched = [
            a for a in first_alerts
            if a.analyzer == "dns_baseline.watched_domain"
        ]
        assert len(first_watched) == 1

        # Second query from same client → no first-query alert
        event2 = _event("clients4.google.com", timestamp=now)
        second_alerts = analyzer.analyze_event(event2)
        second_watched = [
            a for a in second_alerts
            if a.analyzer == "dns_baseline.watched_domain"
        ]
        assert len(second_watched) == 0

    def test_volume_spike_alert(self, store: EventStore) -> None:
        """Should alert when per-client hourly volume exceeds threshold."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["*.doubleclick.net"],
            watched_domain_volume_threshold=5,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        volume_alerts = []
        for _ in range(6):
            event = _event("static.doubleclick.net", timestamp=now)
            alerts = analyzer.analyze_event(event)
            volume_alerts.extend(
                a for a in alerts if a.analyzer == "dns_baseline.watched_volume"
            )

        assert len(volume_alerts) == 1
        assert "volume spike" in volume_alerts[0].title.lower()
        assert volume_alerts[0].severity.value == "medium"

    def test_volume_per_client_isolation(self, store: EventStore) -> None:
        """Different clients should have separate volume counters."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["clients4.google.com"],
            watched_domain_volume_threshold=4,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        now = datetime.now(timezone.utc)
        # 3 queries from each of 2 clients — neither hits threshold of 4
        for client in ["192.168.1.10", "192.168.1.20"]:
            for _ in range(3):
                event = _event(
                    "clients4.google.com", client=client, timestamp=now,
                )
                alerts = analyzer.analyze_event(event)
                vol = [
                    a for a in alerts
                    if a.analyzer == "dns_baseline.watched_volume"
                ]
                assert len(vol) == 0

    def test_wildcard_matching(self, store: EventStore) -> None:
        """Wildcard watched domains should match subdomains."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["*.clients.l.google.com"],
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        # Subdomain match
        event = _event("clients4.clients.l.google.com")
        alerts = analyzer.analyze_event(event)
        watched = [a for a in alerts if a.analyzer == "dns_baseline.watched_domain"]
        assert len(watched) == 1

        # Parent match
        event2 = _event("clients.l.google.com")
        alerts2 = analyzer.analyze_event(event2)
        watched2 = [a for a in alerts2 if a.analyzer == "dns_baseline.watched_domain"]
        assert len(watched2) == 1

    def test_non_watched_domain_no_alert(self, store: EventStore) -> None:
        """Domains not in the watched list should not trigger watched alerts."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["*.doubleclick.net"],
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        event = _event("safe.example.com")
        alerts = analyzer.analyze_event(event)
        watched = [
            a for a in alerts
            if a.analyzer in ("dns_baseline.watched_domain",
                              "dns_baseline.watched_volume")
        ]
        assert len(watched) == 0

    def test_empty_watched_list_no_alerts(self, store: EventStore) -> None:
        """Empty watched_domains list should generate no watched alerts."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=[],
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        event = _event("static.doubleclick.net")
        alerts = analyzer.analyze_event(event)
        watched = [
            a for a in alerts
            if a.analyzer in ("dns_baseline.watched_domain",
                              "dns_baseline.watched_volume")
        ]
        assert len(watched) == 0

    def test_hour_boundary_resets_volume(self, store: EventStore) -> None:
        """Volume counters should reset on hour change."""
        config = AnalyzerConfig(
            known_bad_patterns=[],
            watched_domains=["*.doubleclick.net"],
            watched_domain_volume_threshold=3,
        )
        analyzer = DNSBaselineAnalyzer(store, config)

        # 2 queries at hour 14
        h14 = datetime(2024, 1, 1, 14, 0, tzinfo=timezone.utc)
        for _ in range(2):
            analyzer.analyze_event(
                _event("static.doubleclick.net", timestamp=h14)
            )

        # Switch to hour 15 — counter should reset
        h15 = datetime(2024, 1, 1, 15, 0, tzinfo=timezone.utc)
        volume_alerts = []
        for _ in range(4):
            alerts = analyzer.analyze_event(
                _event("static.doubleclick.net", timestamp=h15)
            )
            volume_alerts.extend(
                a for a in alerts if a.analyzer == "dns_baseline.watched_volume"
            )

        # Should fire at count=3 within hour 15 only
        assert len(volume_alerts) == 1
