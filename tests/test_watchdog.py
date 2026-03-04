"""Tests for the OODA Watchdog."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentmon.llm.anthropic_client import CompletionResult
from agentmon.models import DNSEvent
from agentmon.storage import EventStore
from agentmon.watchdog.models import (
    OODAConcern,
    OODASnapshot,
    SelfAwarenessMetrics,
    WatchdogReport,
)
from agentmon.watchdog.ooda import OODAWatchdog
from agentmon.watchdog.queries import (
    get_new_domains_count,
    get_recent_activity_snapshot,
    get_recent_alerts_summary,
    get_top_clients_recent,
    get_top_domains_recent,
)


def _make_completion(text: str) -> CompletionResult:
    """Helper to build a CompletionResult with dummy token counts."""
    return CompletionResult(text=text, input_tokens=100, output_tokens=50)


@pytest.fixture()
def store() -> EventStore:
    """Create an in-memory EventStore."""
    s = EventStore(Path(":memory:"))
    s.connect()
    yield s
    s.close()


@pytest.fixture()
def populated_store(store: EventStore) -> EventStore:
    """Store with some DNS events for query testing."""
    now = datetime.now(timezone.utc)
    events = [
        DNSEvent(timestamp=now, client="192.168.1.100", domain="example.com", query_type="A", blocked=False),
        DNSEvent(timestamp=now, client="192.168.1.100", domain="google.com", query_type="A", blocked=False),
        DNSEvent(timestamp=now, client="192.168.1.101", domain="example.com", query_type="A", blocked=True),
        DNSEvent(timestamp=now, client="192.168.1.101", domain="malware.bad", query_type="A", blocked=True),
    ]
    store.insert_dns_events_batch(events)
    return store


@pytest.fixture()
def mock_llm() -> MagicMock:
    """Mock AnthropicClient."""
    llm = MagicMock()
    llm.available = True
    llm.config = MagicMock()
    llm.config.model = "claude-sonnet-4-6"
    return llm


# =========================================================================
# SelfAwarenessMetrics Tests
# =========================================================================


class TestSelfAwarenessMetrics:
    """Tests for self-awareness metric tracking."""

    def test_initial_state(self) -> None:
        metrics = SelfAwarenessMetrics()
        assert metrics.total_cycles == 0
        assert metrics.total_cost_usd == 0.0
        assert metrics.avg_latency_ms == 0.0

    def test_update_cycle(self) -> None:
        metrics = SelfAwarenessMetrics()
        metrics.update_cycle(100, 50, 500.0, 0.001)

        assert metrics.total_cycles == 1
        assert metrics.total_input_tokens == 100
        assert metrics.total_output_tokens == 50
        assert metrics.total_cost_usd == 0.001
        assert metrics.avg_latency_ms == 500.0

    def test_multiple_cycles(self) -> None:
        metrics = SelfAwarenessMetrics()
        metrics.update_cycle(100, 50, 400.0, 0.001)
        metrics.update_cycle(200, 100, 600.0, 0.002)

        assert metrics.total_cycles == 2
        assert metrics.total_input_tokens == 300
        assert metrics.avg_latency_ms == 500.0

    def test_to_prompt_section(self) -> None:
        metrics = SelfAwarenessMetrics()
        metrics.update_cycle(100, 50, 500.0, 0.001)
        section = metrics.to_prompt_section()

        assert "Cycles completed: 1" in section
        assert "Total tokens" in section
        assert "Total cost" in section


# =========================================================================
# OODASnapshot Tests
# =========================================================================


class TestOODASnapshot:
    """Tests for snapshot data model."""

    def test_to_dict(self) -> None:
        snapshot = OODASnapshot(
            total_queries=100,
            unique_domains=20,
            new_domains_count=5,
            blocked_count=3,
            top_clients=[{"client": "192.168.1.100", "query_count": 50}],
            top_domains=[{"domain": "example.com", "query_count": 30}],
            recent_alerts=[],
        )
        d = snapshot.to_dict()

        assert d["total_queries"] == 100
        assert d["unique_domains"] == 20
        assert len(d["top_clients"]) == 1


# =========================================================================
# Watchdog Query Tests
# =========================================================================


class TestWatchdogQueries:
    """Tests for DuckDB queries used in the Observe phase."""

    def test_recent_activity_snapshot_empty(self, store: EventStore) -> None:
        result = get_recent_activity_snapshot(store.conn, window_minutes=30)
        assert result["total_queries"] == 0

    def test_recent_activity_snapshot_with_data(self, populated_store: EventStore) -> None:
        result = get_recent_activity_snapshot(populated_store.conn, window_minutes=30)
        assert result["total_queries"] == 4
        assert result["unique_domains"] == 3
        assert result["blocked_count"] == 2

    def test_top_clients(self, populated_store: EventStore) -> None:
        clients = get_top_clients_recent(populated_store.conn, window_minutes=30)
        assert len(clients) == 2
        assert clients[0]["query_count"] == 2

    def test_top_domains(self, populated_store: EventStore) -> None:
        domains = get_top_domains_recent(populated_store.conn, window_minutes=30)
        assert len(domains) == 3
        # example.com queried by both clients
        example = next(d for d in domains if d["domain"] == "example.com")
        assert example["client_count"] == 2

    def test_recent_alerts_empty(self, store: EventStore) -> None:
        alerts = get_recent_alerts_summary(store.conn, window_minutes=30)
        assert len(alerts) == 0

    def test_new_domains_count_all_new(self, populated_store: EventStore) -> None:
        """Without baseline, all domains are 'new'."""
        count = get_new_domains_count(populated_store.conn, window_minutes=30)
        assert count >= 3

    def test_new_domains_count_with_baseline(self, populated_store: EventStore) -> None:
        """Domains in baseline are not counted as new."""
        now = datetime.now(timezone.utc)
        populated_store.update_domain_baseline("192.168.1.100", "example.com", now)
        populated_store.update_domain_baseline("192.168.1.100", "google.com", now)
        populated_store.update_domain_baseline("192.168.1.101", "example.com", now)

        count = get_new_domains_count(populated_store.conn, window_minutes=30)
        # Only malware.bad for client 101 is not in baseline
        assert count == 1


# =========================================================================
# OODAWatchdog Tests
# =========================================================================


class TestOODAWatchdog:
    """Tests for the main watchdog OODA loop."""

    def test_run_cycle_no_traffic(self, store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle with no traffic skips LLM call."""
        watchdog = OODAWatchdog(store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "skipped_no_traffic"
        assert len(report.concerns) == 0
        mock_llm.complete_with_usage.assert_not_called()

    def test_run_cycle_with_traffic(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle with traffic calls LLM and parses response."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Normal traffic",
            "concerns": [],
            "operational_note": "All clear",
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.cycle_number == 1
        assert report.snapshot.total_queries == 4
        assert len(report.concerns) == 0
        mock_llm.complete_with_usage.assert_called_once()

    def test_run_cycle_with_concerns(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle with concerns creates alerts for 'alert' actions."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Suspicious activity detected",
            "concerns": [
                {
                    "title": "Unusual malware domain",
                    "description": "Device querying known malware domain",
                    "severity": "high",
                    "confidence": 0.9,
                    "recommended_action": "alert",
                    "affected_clients": ["192.168.1.101"],
                    "affected_domains": ["malware.bad"],
                },
                {
                    "title": "Slightly elevated traffic",
                    "description": "Minor traffic increase",
                    "severity": "info",
                    "confidence": 0.3,
                    "recommended_action": "monitor",
                    "affected_clients": [],
                    "affected_domains": [],
                },
            ],
            "operational_note": "",
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 2
        # Only "alert" concern should create an Alert in the store
        alerts = populated_store.get_unacknowledged_alerts()
        watchdog_alerts = [a for a in alerts if a["analyzer"] == "watchdog"]
        assert len(watchdog_alerts) == 1
        assert "Watchdog" in watchdog_alerts[0]["title"]

    def test_run_cycle_llm_returns_none(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle handles LLM returning None gracefully."""
        mock_llm.complete_with_usage.return_value = None

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 0

    def test_run_cycle_llm_returns_invalid_json(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle handles invalid JSON from LLM gracefully."""
        mock_llm.complete_with_usage.return_value = _make_completion("This is not JSON")

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 0

    def test_run_cycle_llm_returns_code_fenced_json(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle handles markdown code-fenced JSON response."""
        mock_llm.complete_with_usage.return_value = _make_completion(
            "```json\n"
            + json.dumps({
                "assessment": "Normal",
                "concerns": [{
                    "title": "Test",
                    "description": "Test concern",
                    "severity": "low",
                    "confidence": 0.5,
                    "recommended_action": "monitor",
                }],
            })
            + "\n```"
        )

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 1

    def test_observation_stored_with_tokens(self, populated_store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle stores observation with real token counts."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Normal",
            "concerns": [],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        watchdog.run_cycle()

        row = populated_store.conn.execute(
            "SELECT input_tokens, output_tokens, estimated_cost_usd "
            "FROM watchdog_observations LIMIT 1"
        ).fetchone()
        assert row is not None
        assert row[0] == 100  # input_tokens from _make_completion
        assert row[1] == 50   # output_tokens from _make_completion
        assert row[2] is not None and row[2] > 0  # estimated_cost_usd

    def test_severity_validation_unknown_defaults_to_medium(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Unrecognized severity from LLM is clamped to 'medium'."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Bad severity",
                "description": "LLM returned nonsense severity",
                "severity": "super_duper",
                "confidence": 0.5,
                "recommended_action": "alert",
                "affected_clients": ["192.168.1.100"],
                "affected_domains": ["test.com"],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 1
        assert report.concerns[0].severity == "medium"

    def test_tune_action_add_allowlist_queued(
        self, populated_store: EventStore, mock_llm: MagicMock, tmp_path: Path
    ) -> None:
        """Tune action is queued for approval, not applied directly."""
        config_file = tmp_path / "agentmon.toml"
        config_file.write_text("[analyzer]\nallowlist = []\n")

        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Benign domain generating alerts",
            "concerns": [{
                "title": "Add crashlytics to allowlist",
                "description": "Repeated benign alerts for crashlytics",
                "severity": "info",
                "confidence": 0.95,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "*.crashlytics.com",
                "affected_clients": [],
                "affected_domains": ["*.crashlytics.com"],
            }],
        }))

        watchdog = OODAWatchdog(
            populated_store, mock_llm, interval_minutes=5, config_path=config_file
        )
        report = watchdog.run_cycle()

        assert "pending:add_allowlist" in report.action_taken
        # Config should NOT have been modified
        import tomli
        with open(config_file, "rb") as f:
            data = tomli.load(f)
        assert data["analyzer"]["allowlist"] == []
        # DB should contain the pending action
        rows = populated_store.get_pending_tunes(status="pending")
        assert len(rows) == 1
        assert rows[0]["tune_value"] == "*.crashlytics.com"

    def test_tune_action_invalid_tune_action_skipped(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Unrecognized tune_action is skipped gracefully."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Bad tune",
                "description": "Invalid tune action",
                "severity": "info",
                "confidence": 0.5,
                "recommended_action": "tune",
                "tune_action": "drop_database",
                "tune_value": "everything",
                "affected_clients": [],
                "affected_domains": [],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "no_action"

    def test_window_defaults_to_double_interval(self, store: EventStore, mock_llm: MagicMock) -> None:
        """Window minutes defaults to 2x interval."""
        watchdog = OODAWatchdog(store, mock_llm, interval_minutes=10)
        assert watchdog.window_minutes == 20

    def test_window_explicit_override(self, store: EventStore, mock_llm: MagicMock) -> None:
        """Explicit window_minutes overrides default."""
        watchdog = OODAWatchdog(store, mock_llm, interval_minutes=10, window_minutes=5)
        assert watchdog.window_minutes == 5

    def test_cycle_increments(self, store: EventStore, mock_llm: MagicMock) -> None:
        """Cycle number increments with each call."""
        watchdog = OODAWatchdog(store, mock_llm, interval_minutes=5)

        r1 = watchdog.run_cycle()
        r2 = watchdog.run_cycle()

        assert r1.cycle_number == 1
        assert r2.cycle_number == 2

    def test_stop(self, store: EventStore, mock_llm: MagicMock) -> None:
        """Stop sets running flag to False."""
        watchdog = OODAWatchdog(store, mock_llm, interval_minutes=5)
        watchdog._running = True
        watchdog.stop()
        assert not watchdog._running


# =========================================================================
# Tune Action Queuing & Validation Tests
# =========================================================================


class TestTuneActionQueuing:
    """Tests for tune action queuing instead of direct config mutation."""

    def test_apply_tune_inserts_into_db(
        self, populated_store: EventStore, mock_llm: MagicMock, tmp_path: Path
    ) -> None:
        """_apply_tune() should insert into DB instead of writing config."""
        config_file = tmp_path / "agentmon.toml"
        config_file.write_text("[analyzer]\nallowlist = []\n")

        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Benign domain",
            "concerns": [{
                "title": "Add to allowlist",
                "description": "Repeated benign alerts",
                "severity": "info",
                "confidence": 0.95,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "*.crashlytics.com",
                "affected_clients": [],
                "affected_domains": ["*.crashlytics.com"],
            }],
        }))

        watchdog = OODAWatchdog(
            populated_store, mock_llm, interval_minutes=5, config_path=config_file
        )
        report = watchdog.run_cycle()

        assert "pending" in report.action_taken

        # Config should NOT have been modified
        import tomli
        with open(config_file, "rb") as f:
            data = tomli.load(f)
        assert data["analyzer"]["allowlist"] == []

        # DB should contain the pending tune action
        rows = populated_store.get_pending_tunes(status="pending")
        assert len(rows) == 1
        assert rows[0]["tune_value"] == "*.crashlytics.com"

    def test_invalid_tune_value_non_dns_chars_rejected(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """tune_value with non-DNS characters should be rejected."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Bad value",
                "description": "Non-DNS chars",
                "severity": "info",
                "confidence": 0.9,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "evil; rm -rf /",
                "affected_clients": [],
                "affected_domains": [],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "no_action"

    def test_invalid_tune_value_bare_wildcard_rejected(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Bare wildcard '*' should be rejected for add_allowlist."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Bare wildcard",
                "description": "Wildcard all",
                "severity": "info",
                "confidence": 0.9,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "*",
                "affected_clients": [],
                "affected_domains": [],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "no_action"

    def test_invalid_tune_value_too_long_rejected(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """tune_value exceeding max length should be rejected."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Too long",
                "description": "Excessively long value",
                "severity": "info",
                "confidence": 0.9,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "a" * 300 + ".com",
                "affected_clients": [],
                "affected_domains": [],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "no_action"

    def test_invalid_known_bad_regex_rejected(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Invalid regex for add_known_bad should be rejected."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Bad regex",
                "description": "Invalid regex",
                "severity": "info",
                "confidence": 0.9,
                "recommended_action": "tune",
                "tune_action": "add_known_bad",
                "tune_value": "[invalid(regex",
                "affected_clients": [],
                "affected_domains": [],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert report.action_taken == "no_action"

    def test_confidence_clamped_to_unit_range(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Confidence values outside [0.0, 1.0] should be clamped."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [
                {
                    "title": "High confidence",
                    "description": "Confidence above 1.0",
                    "severity": "medium",
                    "confidence": 99.0,
                    "recommended_action": "monitor",
                    "affected_clients": [],
                    "affected_domains": [],
                },
                {
                    "title": "Negative confidence",
                    "description": "Confidence below 0.0",
                    "severity": "low",
                    "confidence": -5.0,
                    "recommended_action": "monitor",
                    "affected_clients": [],
                    "affected_domains": [],
                },
            ],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert len(report.concerns) == 2
        assert report.concerns[0].confidence == 1.0
        assert report.concerns[1].confidence == 0.0

    def test_valid_values_queued_as_pending(
        self, populated_store: EventStore, mock_llm: MagicMock
    ) -> None:
        """Valid tune values are queued as pending in the DB."""
        mock_llm.complete_with_usage.return_value = _make_completion(json.dumps({
            "assessment": "Test",
            "concerns": [{
                "title": "Valid tune",
                "description": "Benign domain",
                "severity": "info",
                "confidence": 0.9,
                "recommended_action": "tune",
                "tune_action": "add_allowlist",
                "tune_value": "*.netflix.com",
                "affected_clients": [],
                "affected_domains": ["*.netflix.com"],
            }],
        }))

        watchdog = OODAWatchdog(populated_store, mock_llm, interval_minutes=5)
        report = watchdog.run_cycle()

        assert "pending" in report.action_taken
        rows = populated_store.get_pending_tunes(status="pending")
        assert len(rows) == 1
        assert rows[0]["tune_action"] == "add_allowlist"
        assert rows[0]["tune_value"] == "*.netflix.com"
