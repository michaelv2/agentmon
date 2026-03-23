"""Volume Anomaly Detection.

Detects statistical anomalies in DNS query volume per device:
1. Query rate spikes — sudden bursts above normal for this time slot
2. Domain diversity bursts — querying many unique domains at once
3. Sustained behavioral shifts — elevated activity over multiple consecutive hours

Uses Welford's online algorithm (stored in DuckDB) for running mean + variance,
then z-score thresholding for anomaly detection. No hardcoded thresholds for
what's "too many queries" — the baseline adapts per device per time slot.

Complements DNSBaselineAnalyzer (what) and DeviceActivityAnalyzer (when) by
detecting how much.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agentmon.models import Alert, DNSEvent, Severity
from agentmon.storage import EventStore

logger = logging.getLogger(__name__)

DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


@dataclass
class VolumeAnomalyConfig:
    """Configuration for volume anomaly detection."""

    enabled: bool = False

    # Learning period before generating alerts (days)
    learning_days: int = 14

    # Z-score threshold for anomaly detection (3.0 ≈ 0.1% false alarm rate)
    sensitivity_sigma: float = 3.0

    # Minimum baseline samples before detecting anomalies
    min_samples: int = 7

    # Absolute minimum thresholds to avoid alerting on tiny volumes
    min_query_threshold: int = 20
    min_domain_threshold: int = 10

    # Consecutive anomalous hours before sustained behavioral shift alert
    sustained_hours: int = 3

    # Alert severities
    spike_severity: Severity = Severity.MEDIUM
    diversity_severity: Severity = Severity.HIGH
    sustained_severity: Severity = Severity.HIGH

    # Named devices for better alert messages
    devices: list[dict] = field(default_factory=list)


class VolumeAnomalyAnalyzer:
    """Detects anomalous DNS query volume patterns per device.

    Learning phase:
        For the first `learning_days`, the analyzer only records volume
        statistics without generating alerts. Welford's algorithm builds
        a running mean and variance per device per time slot.

    Detection phase:
        After the learning period, if a device's query count or unique
        domain count exceeds the baseline by `sensitivity_sigma` standard
        deviations (z-score), an anomaly alert is generated.

    Hour boundary evaluation:
        Volume is evaluated at hour boundaries, mirroring DeviceActivityAnalyzer:
        1. Count queries and unique domains from the previous hour
        2. Check for rate spike (query count z-score)
        3. Check for diversity burst (domain count z-score)
        4. Track sustained anomalies across consecutive hours
        5. Update baseline with Welford algorithm
    """

    def __init__(self, store: EventStore, config: VolumeAnomalyConfig) -> None:
        self.store = store
        self.config = config

        # Per-device counters for the current hour
        self._hourly_query_counts: dict[str, int] = {}
        self._hourly_domain_sets: dict[str, set[str]] = {}

        # Track consecutive anomalous hours per device for sustained detection
        self._sustained_anomaly_counts: dict[str, int] = {}

        # Current time slot tracking
        self._current_hour: int = -1
        self._current_day: int = -1

        # IP -> device name lookup
        self._ip_to_name: dict[str, str] = {}
        for device in config.devices:
            name = device.get("name", "")
            for ip in device.get("client_ips", []):
                self._ip_to_name[ip] = name

    def _get_device_name(self, client: str) -> str:
        """Get human-readable name for a device, or the IP if unknown."""
        return self._ip_to_name.get(client, client)

    def _past_learning_period(self, client: str) -> bool:
        """Check if a device has passed the learning period."""
        first_seen = self.store.get_volume_first_observation(client)
        if first_seen is None:
            return False

        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)

        now = datetime.now(first_seen.tzinfo)
        days_observed = (now - first_seen).days
        return days_observed >= self.config.learning_days

    def analyze_event(self, event: DNSEvent) -> list[Alert]:
        """Track volume and check for anomalies at hour boundaries.

        Args:
            event: DNS event to analyze.

        Returns:
            List of alerts (may be empty).
        """
        current_hour = event.timestamp.hour
        current_day = event.timestamp.weekday()
        alerts: list[Alert] = []

        if self._current_hour == -1:
            # First event — initialize time slot
            self._current_hour = current_hour
            self._current_day = current_day
        elif current_hour != self._current_hour or current_day != self._current_day:
            # Hour boundary crossed — evaluate previous hour before tracking new event
            alerts = self._evaluate_previous_hour(event.timestamp)

        # Track query count (in the new/current hour)
        client = event.client
        self._hourly_query_counts[client] = self._hourly_query_counts.get(client, 0) + 1

        # Track unique domains
        if client not in self._hourly_domain_sets:
            self._hourly_domain_sets[client] = set()
        self._hourly_domain_sets[client].add(event.domain)

        return alerts

    def _evaluate_previous_hour(self, now: datetime) -> list[Alert]:
        """At hour boundary, evaluate all devices and update baselines.

        Three detection layers:
        1. Query rate spike — z-score on query count
        2. Domain diversity burst — z-score on unique domain count
        3. Sustained elevation — consecutive anomalous hours

        Args:
            now: Current timestamp (in the new hour).

        Returns:
            List of alerts.
        """
        alerts: list[Alert] = []

        # Calculate previous hour's time slot
        if now.hour == 0:
            prev_hour = 23
            prev_day = (now.weekday() - 1) % 7
        else:
            prev_hour = now.hour - 1
            prev_day = now.weekday()

        logger.debug(
            f"Volume evaluation: {DAY_NAMES[prev_day]} {prev_hour}:00 "
            f"({len(self._hourly_query_counts)} devices)"
        )

        for client in set(self._hourly_query_counts.keys()) | set(self._hourly_domain_sets.keys()):
            query_count = self._hourly_query_counts.get(client, 0)
            domain_count = len(self._hourly_domain_sets.get(client, set()))

            any_anomaly = False

            # Only check anomalies after learning period
            if self._past_learning_period(client):
                # Layer 1: Query rate spike
                if query_count >= self.config.min_query_threshold:
                    is_anomaly, z_score = self.store.is_volume_anomalous(
                        client, prev_day, prev_hour, float(query_count),
                        metric="query_count",
                        sigma=self.config.sensitivity_sigma,
                        min_samples=self.config.min_samples,
                    )
                    if is_anomaly:
                        any_anomaly = True
                        alert = self._create_rate_spike_alert(
                            client, prev_day, prev_hour, query_count, z_score
                        )
                        alerts.append(alert)
                        logger.info(
                            f"Rate spike: {self._get_device_name(client)} "
                            f"at {DAY_NAMES[prev_day]} {prev_hour}:00 "
                            f"(queries={query_count}, z={z_score:.2f})"
                        )

                # Layer 2: Domain diversity burst
                if domain_count >= self.config.min_domain_threshold:
                    is_anomaly, z_score = self.store.is_volume_anomalous(
                        client, prev_day, prev_hour, float(domain_count),
                        metric="domain_count",
                        sigma=self.config.sensitivity_sigma,
                        min_samples=self.config.min_samples,
                    )
                    if is_anomaly:
                        any_anomaly = True
                        alert = self._create_diversity_burst_alert(
                            client, prev_day, prev_hour, domain_count, z_score
                        )
                        alerts.append(alert)
                        logger.info(
                            f"Diversity burst: {self._get_device_name(client)} "
                            f"at {DAY_NAMES[prev_day]} {prev_hour}:00 "
                            f"(domains={domain_count}, z={z_score:.2f})"
                        )

                # Layer 3: Sustained elevation tracking
                if any_anomaly:
                    self._sustained_anomaly_counts[client] = (
                        self._sustained_anomaly_counts.get(client, 0) + 1
                    )
                    if self._sustained_anomaly_counts[client] == self.config.sustained_hours:
                        alert = self._create_sustained_alert(
                            client, prev_day, prev_hour,
                            self._sustained_anomaly_counts[client],
                        )
                        alerts.append(alert)
                        logger.info(
                            f"Sustained elevation: {self._get_device_name(client)} "
                            f"for {self._sustained_anomaly_counts[client]} hours"
                        )
                else:
                    # Reset sustained counter on normal hour
                    self._sustained_anomaly_counts.pop(client, None)

            # Update baseline with Welford algorithm
            self.store.update_volume_baseline(
                client, prev_day, prev_hour, query_count, domain_count
            )

        # Clear counters for new hour
        self._hourly_query_counts.clear()
        self._hourly_domain_sets.clear()
        self._current_hour = now.hour
        self._current_day = now.weekday()

        return alerts

    def _create_rate_spike_alert(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        query_count: int,
        z_score: float,
    ) -> Alert:
        """Create an alert for a query rate spike."""
        device_name = self._get_device_name(client)
        hour_str = f"{hour_of_day:02d}:00"

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            severity=self.config.spike_severity,
            title=f"Query rate spike: {device_name} at {hour_str}",
            description=(
                f"Device {device_name} ({client}) made {query_count} DNS queries "
                f"at {hour_str} on {DAY_NAMES[day_of_week]}, which is {z_score:.1f} "
                f"standard deviations above the baseline for this time slot."
            ),
            source_event_type="dns",
            client=client,
            analyzer="volume_anomaly",
            confidence=min(z_score / 5.0, 1.0),
            tags=["rate_spike"],
        )

    def _create_diversity_burst_alert(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        domain_count: int,
        z_score: float,
    ) -> Alert:
        """Create an alert for a domain diversity burst."""
        device_name = self._get_device_name(client)
        hour_str = f"{hour_of_day:02d}:00"

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            severity=self.config.diversity_severity,
            title=f"Domain diversity burst: {device_name} at {hour_str}",
            description=(
                f"Device {device_name} ({client}) queried {domain_count} unique domains "
                f"at {hour_str} on {DAY_NAMES[day_of_week]}, which is {z_score:.1f} "
                f"standard deviations above the baseline for this time slot."
            ),
            source_event_type="dns",
            client=client,
            analyzer="volume_anomaly",
            confidence=min(z_score / 5.0, 1.0),
            tags=["diversity_burst"],
        )

    def _create_sustained_alert(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        consecutive_hours: int,
    ) -> Alert:
        """Create an alert for sustained elevated activity."""
        device_name = self._get_device_name(client)
        hour_str = f"{hour_of_day:02d}:00"

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            severity=self.config.sustained_severity,
            title=f"Sustained elevated activity: {device_name} for {consecutive_hours}h",
            description=(
                f"Device {device_name} ({client}) has shown anomalous volume for "
                f"{consecutive_hours} consecutive hours ending at {hour_str} on "
                f"{DAY_NAMES[day_of_week]}. This suggests a behavioral shift rather "
                f"than a transient spike."
            ),
            source_event_type="dns",
            client=client,
            analyzer="volume_anomaly",
            confidence=0.9,
            tags=["behavioral_shift"],
        )

    def flush(self) -> None:
        """Persist partial hour data without alerting (for shutdown).

        Records the current hour's data to the baseline but does not
        generate alerts for incomplete hours.
        """
        if not self._hourly_query_counts and not self._hourly_domain_sets:
            return

        now = datetime.now(UTC)
        for client in set(self._hourly_query_counts.keys()) | set(self._hourly_domain_sets.keys()):
            query_count = self._hourly_query_counts.get(client, 0)
            domain_count = len(self._hourly_domain_sets.get(client, set()))
            self.store.update_volume_baseline(
                client, now.weekday(), now.hour, query_count, domain_count
            )

        self._hourly_query_counts.clear()
        self._hourly_domain_sets.clear()
