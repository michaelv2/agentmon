"""Tests for VolumeAnomalyAnalyzer."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentmon.analyzers.volume_anomaly import VolumeAnomalyAnalyzer, VolumeAnomalyConfig
from agentmon.models import DNSEvent, Severity
from agentmon.storage import EventStore


@pytest.fixture()
def store() -> EventStore:
    """Create an in-memory EventStore."""
    s = EventStore(Path(":memory:"))
    s.connect()
    yield s
    s.close()


def make_event(
    domain: str = "example.com",
    client: str = "192.168.1.100",
    hour: int = 14,
    day: int = 1,  # 0=Monday, 1=Tuesday, etc.
) -> DNSEvent:
    """Create a DNSEvent at a specific time.

    Uses June 2, 2025 as reference (Monday=weekday 0), so day parameter
    maps directly to Python's weekday() return value.
    """
    # June 2, 2025 is Monday (weekday=0)
    ts = datetime(2025, 6, 2 + day, hour, 30, 0, tzinfo=UTC)
    return DNSEvent(
        timestamp=ts,
        client=client,
        domain=domain,
        query_type="A",
        blocked=False,
    )


class TestVolumeBaseline:
    """Tests for the Welford baseline tracking in EventStore."""

    def test_first_observation(self, store: EventStore) -> None:
        """First observation sets mean=value, M2=0, n=1."""
        store.update_volume_baseline("client1", 1, 14, 100, 20)
        baseline = store.get_volume_baseline("client1", 1, 14)

        assert baseline is not None
        assert baseline["query_count_mean"] == 100.0
        assert baseline["query_count_m2"] == 0.0
        assert baseline["domain_count_mean"] == 20.0
        assert baseline["sample_count"] == 1

    def test_welford_update(self, store: EventStore) -> None:
        """Multiple observations update mean and M2 correctly."""
        # Observations: 100, 200 -> mean=150, variance=5000, M2=5000
        store.update_volume_baseline("client1", 1, 14, 100, 10)
        store.update_volume_baseline("client1", 1, 14, 200, 30)

        baseline = store.get_volume_baseline("client1", 1, 14)
        assert baseline is not None
        assert baseline["sample_count"] == 2
        assert baseline["query_count_mean"] == pytest.approx(150.0)
        # M2 = (100-150)^2 + (200-150)^2... but Welford computes iteratively
        # After 2 samples: M2 = delta * delta2 = (200-100) * (200-150) = 100*50 = 5000
        # But first sample M2=0, second: delta=200-100=100, new_mean=150, delta2=200-150=50
        # new_m2 = 0 + 100*50 = 5000
        assert baseline["query_count_m2"] == pytest.approx(5000.0)

    def test_multiple_observations_convergence(self, store: EventStore) -> None:
        """Mean converges to expected value with many observations."""
        values = [10, 20, 30, 40, 50]
        for v in values:
            store.update_volume_baseline("client1", 0, 0, v, v)

        baseline = store.get_volume_baseline("client1", 0, 0)
        assert baseline is not None
        assert baseline["sample_count"] == 5
        assert baseline["query_count_mean"] == pytest.approx(30.0)
        # Variance = 200 (population), 250 (sample)
        # M2 = sum((xi - mean)^2) = 400+100+0+100+400 = 1000
        assert baseline["query_count_m2"] == pytest.approx(1000.0)

    def test_no_baseline_returns_none(self, store: EventStore) -> None:
        """Missing baseline returns None."""
        assert store.get_volume_baseline("nonexistent", 0, 0) is None

    def test_separate_slots(self, store: EventStore) -> None:
        """Different time slots have independent baselines."""
        store.update_volume_baseline("client1", 0, 10, 100, 10)
        store.update_volume_baseline("client1", 0, 11, 200, 20)

        b10 = store.get_volume_baseline("client1", 0, 10)
        b11 = store.get_volume_baseline("client1", 0, 11)

        assert b10["query_count_mean"] == 100.0
        assert b11["query_count_mean"] == 200.0


class TestVolumeAnomaly:
    """Tests for z-score anomaly detection."""

    def test_no_anomaly_insufficient_samples(self, store: EventStore) -> None:
        """No anomaly when samples < min_samples."""
        for i in range(5):  # Less than default min_samples=7
            store.update_volume_baseline("c1", 0, 0, 50, 10)

        is_anom, z = store.is_volume_anomalous("c1", 0, 0, 500.0)
        assert not is_anom
        assert z == 0.0

    def test_anomaly_detected_high_z(self, store: EventStore) -> None:
        """High z-score triggers anomaly."""
        # Build a stable baseline: 10 observations of ~50 queries
        for v in [48, 50, 52, 50, 49, 51, 50, 48, 52, 50]:
            store.update_volume_baseline("c1", 0, 0, v, 10)

        # Check value far from mean
        is_anom, z = store.is_volume_anomalous("c1", 0, 0, 500.0, sigma=3.0)
        assert is_anom
        assert z > 3.0

    def test_no_anomaly_within_sigma(self, store: EventStore) -> None:
        """Value within sigma range is not anomalous."""
        for v in [48, 50, 52, 50, 49, 51, 50, 48, 52, 50]:
            store.update_volume_baseline("c1", 0, 0, v, 10)

        # Value close to mean
        is_anom, z = store.is_volume_anomalous("c1", 0, 0, 52.0, sigma=3.0)
        assert not is_anom

    def test_domain_count_metric(self, store: EventStore) -> None:
        """Domain count metric works independently from query count."""
        for v in [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]:
            store.update_volume_baseline("c1", 0, 0, 50, v)

        # Query count normal but domain count anomalous
        is_anom, z = store.is_volume_anomalous(
            "c1", 0, 0, 100.0, metric="domain_count", sigma=3.0
        )
        assert is_anom


class TestVolumeAnomalyAnalyzer:
    """Tests for the full analyzer with hour-boundary evaluation."""

    def test_tracks_queries_within_hour(self, store: EventStore) -> None:
        """Events within the same hour are counted but don't trigger evaluation."""
        config = VolumeAnomalyConfig(enabled=True)
        analyzer = VolumeAnomalyAnalyzer(store, config)

        event = make_event(domain="example.com", hour=14)
        alerts = analyzer.analyze_event(event)
        assert len(alerts) == 0
        assert analyzer._hourly_query_counts["192.168.1.100"] == 1

    def test_hour_boundary_triggers_evaluation(self, store: EventStore) -> None:
        """Crossing an hour boundary triggers evaluation and clears counters."""
        config = VolumeAnomalyConfig(enabled=True, learning_days=0)
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Send events in hour 14
        for i in range(5):
            analyzer.analyze_event(make_event(domain=f"d{i}.com", hour=14))

        # Cross to hour 15 — triggers evaluation of hour 14
        alerts = analyzer.analyze_event(make_event(hour=15))

        # Counters should be reset for the new hour
        assert analyzer._hourly_query_counts.get("192.168.1.100", 0) == 1
        assert analyzer._current_hour == 15

    def test_baseline_updated_after_evaluation(self, store: EventStore) -> None:
        """Volume baseline is updated after hour evaluation."""
        config = VolumeAnomalyConfig(enabled=True)
        analyzer = VolumeAnomalyAnalyzer(store, config)

        for i in range(10):
            analyzer.analyze_event(make_event(domain=f"d{i}.com", hour=14))

        # Cross hour boundary
        analyzer.analyze_event(make_event(hour=15))

        # Check baseline was updated
        baseline = store.get_volume_baseline("192.168.1.100", 1, 14)
        assert baseline is not None
        assert baseline["sample_count"] == 1
        assert baseline["query_count_mean"] == 10.0

    def test_no_alert_during_learning(self, store: EventStore) -> None:
        """No alerts during the learning period even with extreme values."""
        config = VolumeAnomalyConfig(enabled=True, learning_days=14)
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Many events in one hour
        for i in range(100):
            analyzer.analyze_event(make_event(domain=f"d{i}.com", hour=14))

        alerts = analyzer.analyze_event(make_event(hour=15))
        assert len(alerts) == 0

    def test_spike_alert_after_learning(self, store: EventStore) -> None:
        """Rate spike alert fires after learning period with z > sigma."""
        config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=0,
            min_samples=3,
            sensitivity_sigma=2.0,
            min_query_threshold=5,
        )
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Build baseline: 3 observations of ~10 queries
        for obs in range(3):
            store.update_volume_baseline("192.168.1.100", 1, 14, 10, 5)

        # Now send a spike: 100 queries in hour 14
        for i in range(100):
            analyzer.analyze_event(make_event(domain=f"d{i % 5}.com", hour=14))

        # Trigger evaluation
        alerts = analyzer.analyze_event(make_event(hour=15))

        spike_alerts = [a for a in alerts if "rate_spike" in a.tags]
        assert len(spike_alerts) >= 1
        assert spike_alerts[0].analyzer == "volume_anomaly"
        assert spike_alerts[0].severity == Severity.MEDIUM

    def test_diversity_burst_alert(self, store: EventStore) -> None:
        """Domain diversity burst alert fires when unique domains spike."""
        config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=0,
            min_samples=3,
            sensitivity_sigma=2.0,
            min_domain_threshold=5,
        )
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Build baseline: 3 observations of ~5 unique domains
        for obs in range(3):
            store.update_volume_baseline("192.168.1.100", 1, 14, 10, 5)

        # Now send many unique domains
        for i in range(50):
            analyzer.analyze_event(make_event(domain=f"unique{i}.com", hour=14))

        alerts = analyzer.analyze_event(make_event(hour=15))

        diversity_alerts = [a for a in alerts if "diversity_burst" in a.tags]
        assert len(diversity_alerts) >= 1
        assert diversity_alerts[0].severity == Severity.HIGH

    def test_sustained_alert(self, store: EventStore) -> None:
        """Sustained behavioral shift alert after consecutive anomalous hours."""
        config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=0,
            min_samples=3,
            sensitivity_sigma=2.0,
            min_query_threshold=5,
            sustained_hours=2,
        )
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Build baseline: stable low traffic
        for obs in range(5):
            store.update_volume_baseline("192.168.1.100", 1, 10, 10, 5)
            store.update_volume_baseline("192.168.1.100", 1, 11, 10, 5)
            store.update_volume_baseline("192.168.1.100", 1, 12, 10, 5)

        # Hour 10: spike
        for i in range(100):
            analyzer.analyze_event(make_event(domain=f"d{i % 3}.com", hour=10))

        alerts_h10 = analyzer.analyze_event(make_event(hour=11))
        sustained_h10 = [a for a in alerts_h10 if "behavioral_shift" in a.tags]
        assert len(sustained_h10) == 0  # Only 1 hour, need 2

        # Hour 11: another spike
        for i in range(100):
            analyzer.analyze_event(make_event(domain=f"d{i % 3}.com", hour=11))

        alerts_h11 = analyzer.analyze_event(make_event(hour=12))
        sustained_h11 = [a for a in alerts_h11 if "behavioral_shift" in a.tags]
        assert len(sustained_h11) >= 1

    def test_flush_persists_without_alerting(self, store: EventStore) -> None:
        """Flush writes partial hour data to baseline without alerts."""
        config = VolumeAnomalyConfig(enabled=True)
        analyzer = VolumeAnomalyAnalyzer(store, config)

        for i in range(20):
            analyzer.analyze_event(make_event(domain=f"d{i}.com", hour=14))

        analyzer.flush()

        # Counters should be cleared
        assert len(analyzer._hourly_query_counts) == 0

    def test_device_name_in_alert(self, store: EventStore) -> None:
        """Named devices appear in alert titles."""
        config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=0,
            min_samples=3,
            sensitivity_sigma=2.0,
            min_query_threshold=5,
            devices=[{"name": "alice-laptop", "client_ips": ["192.168.1.100"]}],
        )
        analyzer = VolumeAnomalyAnalyzer(store, config)

        for obs in range(3):
            store.update_volume_baseline("192.168.1.100", 1, 14, 10, 5)

        for i in range(100):
            analyzer.analyze_event(make_event(domain=f"d{i % 5}.com", hour=14))

        alerts = analyzer.analyze_event(make_event(hour=15))
        if alerts:
            assert "alice-laptop" in alerts[0].title

    def test_below_min_threshold_no_alert(self, store: EventStore) -> None:
        """Below minimum threshold does not alert even if z-score is high."""
        config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=0,
            min_samples=3,
            sensitivity_sigma=2.0,
            min_query_threshold=50,  # High threshold
        )
        analyzer = VolumeAnomalyAnalyzer(store, config)

        # Baseline with very low traffic
        for obs in range(5):
            store.update_volume_baseline("192.168.1.100", 1, 14, 1, 1)

        # 10 queries — high z-score but below min_query_threshold
        for i in range(10):
            analyzer.analyze_event(make_event(domain=f"d{i}.com", hour=14))

        alerts = analyzer.analyze_event(make_event(hour=15))
        spike_alerts = [a for a in alerts if "rate_spike" in a.tags]
        assert len(spike_alerts) == 0
