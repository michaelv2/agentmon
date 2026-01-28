"""Device Activity Anomaly Detection.

Learns each device's normal activity hours and alerts when activity occurs
outside those patterns - without requiring hard-coded time rules.

This is complementary to parental controls:
- Parental controls: Hard-coded rules ("block games 3-5pm")
- Device activity: Learned baseline ("alert if active at 3am")

Example use case:
    Device 192.168.1.50 normally shows DNS activity from 7am-10pm.
    At 3:15 AM, it suddenly starts querying domains.
    Alert: "Unusual activity detected outside normal hours"
"""

from dataclasses import dataclass, field
from datetime import datetime
import logging
import uuid

from agentmon.models import Alert, DNSEvent, Severity
from agentmon.storage import EventStore

logger = logging.getLogger(__name__)

# Day name mapping for human-readable alerts
DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


@dataclass
class DeviceActivityConfig:
    """Configuration for device activity anomaly detection."""

    enabled: bool = False

    # Learning period before generating alerts (days)
    learning_days: int = 14

    # Minimum queries in an hour to consider device "active"
    activity_threshold: int = 5

    # Minimum samples per time slot before detecting anomalies
    min_samples: int = 7

    # Alert severity for activity anomalies
    alert_severity: Severity = Severity.MEDIUM

    # Named devices for better alert messages
    # List of dicts with: name, client_ips, always_active (optional)
    devices: list[dict] = field(default_factory=list)


class DeviceActivityAnalyzer:
    """Analyzes device activity patterns and detects anomalies.

    Learning phase:
        For the first `learning_days`, the analyzer only records activity
        patterns without generating alerts. It tracks:
        - Which hours each device is typically active (>= threshold queries)
        - How often each time slot (day-of-week + hour) sees activity

    Detection phase:
        After the learning period, if a device becomes active during a time
        slot where it's historically inactive (<10% activity ratio), an
        anomaly alert is generated.

    Hour boundary evaluation:
        Activity is evaluated at hour boundaries. When a new hour starts,
        the analyzer:
        1. Counts queries from the previous hour
        2. Checks if device was "active" (count >= threshold)
        3. If active and this slot is usually inactive -> alert
        4. Updates the baseline with this observation
    """

    def __init__(self, store: EventStore, config: DeviceActivityConfig):
        self.store = store
        self.config = config

        # Track queries per device in the current hour
        self._hourly_counts: dict[str, int] = {}

        # Track the current hour to detect hour boundaries
        self._current_hour: int = -1
        self._current_day: int = -1

        # Build IP -> device name lookup for better alert messages
        self._ip_to_name: dict[str, str] = {}
        self._always_active: set[str] = set()

        for device in config.devices:
            name = device.get("name", "")
            client_ips = device.get("client_ips", [])
            always_active = device.get("always_active", False)

            for ip in client_ips:
                self._ip_to_name[ip] = name
                if always_active:
                    self._always_active.add(ip)

    def _get_device_name(self, client: str) -> str:
        """Get the human-readable name for a device, or the IP if unknown."""
        return self._ip_to_name.get(client, client)

    def _is_always_active(self, client: str) -> bool:
        """Check if a device is marked as always-active (e.g., servers)."""
        return client in self._always_active

    def _past_learning_period(self, client: str) -> bool:
        """Check if a device has passed the learning period."""
        first_seen = self.store.get_device_first_activity(client)
        if first_seen is None:
            return False

        # Make first_seen offset-aware if needed
        if first_seen.tzinfo is None:
            from datetime import timezone
            first_seen = first_seen.replace(tzinfo=timezone.utc)

        now = datetime.now(first_seen.tzinfo)
        days_observed = (now - first_seen).days
        return days_observed >= self.config.learning_days

    def analyze_event(self, event: DNSEvent) -> list[Alert]:
        """Track activity and check for anomalies.

        Args:
            event: DNS event to analyze

        Returns:
            List of alerts (may be empty)
        """
        # Skip always-active devices
        if self._is_always_active(event.client):
            return []

        # Track activity
        self._track_activity(event)

        # Check if we've crossed into a new hour
        current_hour = event.timestamp.hour
        current_day = event.timestamp.weekday()

        if self._should_evaluate_hour(current_day, current_hour):
            return self._evaluate_previous_hour(event.timestamp)

        return []

    def _track_activity(self, event: DNSEvent) -> None:
        """Increment counter for this device in current hour."""
        client = event.client
        self._hourly_counts[client] = self._hourly_counts.get(client, 0) + 1

    def _should_evaluate_hour(self, current_day: int, current_hour: int) -> bool:
        """Check if we've moved to a new hour and should evaluate the previous one."""
        if self._current_hour == -1:
            # First event - initialize but don't evaluate
            self._current_hour = current_hour
            self._current_day = current_day
            return False

        if current_hour != self._current_hour or current_day != self._current_day:
            return True

        return False

    def _evaluate_previous_hour(self, now: datetime) -> list[Alert]:
        """At hour boundary, evaluate all devices and update baseline.

        Args:
            now: Current timestamp (in the new hour)

        Returns:
            List of alerts for anomalous activity
        """
        alerts = []

        # Calculate previous hour's day/hour
        if now.hour == 0:
            # Rolled over midnight - previous hour was 23, previous day
            prev_hour = 23
            prev_day = (now.weekday() - 1) % 7
        else:
            prev_hour = now.hour - 1
            prev_day = now.weekday()

        logger.debug(
            f"Evaluating hour boundary: {DAY_NAMES[prev_day]} {prev_hour}:00 "
            f"({len(self._hourly_counts)} devices active)"
        )

        for client, count in self._hourly_counts.items():
            # Skip always-active devices
            if self._is_always_active(client):
                continue

            was_active = count >= self.config.activity_threshold

            # Check for anomaly (only after learning period)
            if was_active and self._past_learning_period(client):
                is_anomaly, active_ratio = self.store.is_device_activity_anomalous(
                    client, prev_day, prev_hour, min_samples=self.config.min_samples
                )

                if is_anomaly:
                    alert = self._create_anomaly_alert(
                        client, prev_day, prev_hour, count, active_ratio
                    )
                    alerts.append(alert)
                    logger.info(
                        f"Activity anomaly detected: {self._get_device_name(client)} "
                        f"at {DAY_NAMES[prev_day]} {prev_hour}:00 "
                        f"(active_ratio={active_ratio:.1%}, queries={count})"
                    )

            # Update baseline with this observation
            self.store.update_device_activity(
                client, prev_day, prev_hour, count, was_active
            )

        # Clear counts for new hour
        self._hourly_counts.clear()
        self._current_hour = now.hour
        self._current_day = now.weekday()

        return alerts

    def _create_anomaly_alert(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        query_count: int,
        active_ratio: float,
    ) -> Alert:
        """Create an alert for anomalous device activity.

        Args:
            client: Device IP address
            day_of_week: 0=Monday through 6=Sunday
            hour_of_day: 0-23
            query_count: Number of queries in this hour
            active_ratio: Historical activity ratio for this time slot

        Returns:
            Alert object
        """
        device_name = self._get_device_name(client)
        day_name = DAY_NAMES[day_of_week]

        # Format hour nicely
        hour_str = f"{hour_of_day:02d}:00"

        title = f"Unusual activity: {device_name} active at {hour_str}"

        description = (
            f"Device {device_name} ({client}) showed activity at {hour_str} on {day_name}, "
            f"but is normally inactive during this time (active only {active_ratio:.0%} of the time). "
            f"Observed {query_count} DNS queries this hour."
        )

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=self.config.alert_severity,
            title=title,
            description=description,
            source_event_type="dns",
            client=client,
            analyzer="device_activity",
            confidence=1.0 - active_ratio,  # Higher confidence when ratio is lower
        )

    def flush(self) -> list[Alert]:
        """Flush any pending activity data.

        Call this when shutting down to ensure the current hour's data
        is recorded (though alerts won't be generated for partial hours).

        Returns:
            Empty list (partial hours don't generate alerts)
        """
        if not self._hourly_counts:
            return []

        # Record partial hour data without alerting
        now = datetime.now()
        for client, count in self._hourly_counts.items():
            if self._is_always_active(client):
                continue

            was_active = count >= self.config.activity_threshold
            self.store.update_device_activity(
                client, now.weekday(), now.hour, count, was_active
            )

        self._hourly_counts.clear()
        return []
