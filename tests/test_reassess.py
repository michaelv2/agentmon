"""Tests for the reassessment feature."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentmon.models import Alert, Severity
from agentmon.reassess.analyzer import ReassessmentAnalyzer
from agentmon.reassess.queries import (
    get_analyzer_false_positive_rates,
    get_high_frequency_alert_domains,
    get_recent_alert_sample,
    get_unflagged_high_traffic_domains,
)
from agentmon.reassess.report import ReassessmentFinding, ReassessmentReport
from agentmon.storage import EventStore


@pytest.fixture
def store() -> EventStore:
    """Create an in-memory EventStore with test data."""
    s = EventStore(Path(":memory:"))
    s.connect()
    return s


@pytest.fixture
def store_with_data(store: EventStore) -> EventStore:
    """EventStore populated with alerts and DNS events for testing."""
    now = datetime.now(UTC)

    # Insert alerts — some domains have many alerts (FP candidates)
    alerts = [
        Alert(
            id=f"alert-fp-{i}",
            timestamp=now,
            severity=Severity.LOW,
            title="New domain: noisy-domain.com",
            description="First seen",
            source_event_type="dns",
            domain="noisy-domain.com",
            client="192.168.1.10",
            analyzer="dns_baseline",
            false_positive=True,
        )
        for i in range(15)
    ] + [
        Alert(
            id=f"alert-nonfp-{i}",
            timestamp=now,
            severity=Severity.MEDIUM,
            title="Suspicious domain: bad-domain.xyz",
            description="High entropy",
            source_event_type="dns",
            domain="bad-domain.xyz",
            client="192.168.1.20",
            analyzer="entropy",
            false_positive=False,
        )
        for i in range(8)
    ] + [
        Alert(
            id=f"alert-mixed-{i}",
            timestamp=now,
            severity=Severity.LOW,
            title="New domain: mixed-domain.net",
            description="First seen",
            source_event_type="dns",
            domain="mixed-domain.net",
            client="192.168.1.30",
            analyzer="dns_baseline",
            false_positive=(i % 2 == 0),
        )
        for i in range(12)
    ]

    for alert in alerts:
        store.insert_alert(alert)

    # Insert DNS events for unflagged domain testing
    from agentmon.models import DNSEvent

    for i in range(10):
        store.insert_dns_event(DNSEvent(
            timestamp=now,
            client=f"192.168.1.{10 + i}",
            domain="popular-unflagged.com",
            query_type="A",
            blocked=False,
        ))

    # Also insert events for flagged domains so they don't show as unflagged
    for i in range(3):
        store.insert_dns_event(DNSEvent(
            timestamp=now,
            client=f"192.168.1.{10 + i}",
            domain="noisy-domain.com",
            query_type="A",
            blocked=False,
        ))

    return store


class TestQueries:
    """Test reassessment queries."""

    def test_high_frequency_alert_domains(self, store_with_data: EventStore) -> None:
        result = get_high_frequency_alert_domains(
            store_with_data.conn, days=7, min_count=5,
        )
        assert len(result) >= 2
        domains = {r["domain"] for r in result}
        assert "noisy-domain.com" in domains
        assert "bad-domain.xyz" in domains

        # noisy-domain.com should have 15 alerts, all FP
        noisy = next(r for r in result if r["domain"] == "noisy-domain.com")
        assert noisy["alert_count"] == 15
        assert noisy["fp_count"] == 15

    def test_unflagged_high_traffic_domains(self, store_with_data: EventStore) -> None:
        result = get_unflagged_high_traffic_domains(
            store_with_data.conn, min_clients=2,
        )
        domains = {r["domain"] for r in result}
        assert "popular-unflagged.com" in domains

        popular = next(r for r in result if r["domain"] == "popular-unflagged.com")
        assert popular["client_count"] == 10

    def test_analyzer_false_positive_rates(self, store_with_data: EventStore) -> None:
        result = get_analyzer_false_positive_rates(store_with_data.conn, days=30)
        assert len(result) >= 1
        analyzers = {r["analyzer"] for r in result}
        assert "dns_baseline" in analyzers

    def test_recent_alert_sample(self, store_with_data: EventStore) -> None:
        result = get_recent_alert_sample(store_with_data.conn, days=7, limit=50)
        assert len(result) > 0
        assert "severity" in result[0]
        assert "domain" in result[0]

    def test_empty_database(self, store: EventStore) -> None:
        """Queries should return empty lists on empty database."""
        assert get_high_frequency_alert_domains(store.conn) == []
        assert get_unflagged_high_traffic_domains(store.conn) == []
        assert get_analyzer_false_positive_rates(store.conn) == []
        assert get_recent_alert_sample(store.conn) == []


class TestHeuristics:
    """Test heuristic finding logic in ReassessmentAnalyzer."""

    def test_allowlist_candidate_found(self, store_with_data: EventStore) -> None:
        analyzer = ReassessmentAnalyzer(store_with_data)
        report = analyzer.analyze(days=7)

        allowlist = [f for f in report.findings if f.category == "allowlist_candidate"]
        assert len(allowlist) >= 1
        domains = {f.domain for f in allowlist}
        assert "noisy-domain.com" in domains

    def test_blind_spot_found(self, store_with_data: EventStore) -> None:
        analyzer = ReassessmentAnalyzer(store_with_data)
        report = analyzer.analyze(days=7)

        blind_spots = [f for f in report.findings if f.category == "blind_spot"]
        domains = {f.domain for f in blind_spots}
        assert "popular-unflagged.com" in domains

    def test_no_llm_by_default(self, store_with_data: EventStore) -> None:
        analyzer = ReassessmentAnalyzer(store_with_data)
        report = analyzer.analyze(days=7)
        assert report.llm_used is False
        assert report.llm_analysis is None


class TestReport:
    """Test report rendering."""

    def test_to_text(self) -> None:
        report = ReassessmentReport(
            days_analyzed=7,
            total_alerts=25,
            total_domains=5,
            findings=[
                ReassessmentFinding(
                    category="allowlist_candidate",
                    title="example.com — 90% FP rate",
                    description="15 alerts, 14 false positives",
                    domain="example.com",
                    severity="action",
                    recommendation="Add to allowlist",
                ),
            ],
        )
        text = report.to_text()
        assert "Reassessment Report" in text
        assert "example.com" in text
        assert "allowlist" in text.lower()

    def test_to_json(self) -> None:
        report = ReassessmentReport(
            days_analyzed=7,
            total_alerts=10,
            total_domains=3,
            findings=[
                ReassessmentFinding(
                    category="blind_spot",
                    title="test.com — 5 clients",
                    description="Never flagged",
                    domain="test.com",
                    severity="info",
                ),
            ],
        )
        data = json.loads(report.to_json())
        assert data["days_analyzed"] == 7
        assert len(data["findings"]) == 1
        assert data["findings"][0]["category"] == "blind_spot"

    def test_empty_report(self) -> None:
        report = ReassessmentReport(days_analyzed=7)
        text = report.to_text()
        assert "well-tuned" in text.lower()
