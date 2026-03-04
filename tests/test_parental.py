"""Tests for parental control overnight time rule day-boundary logic."""

from datetime import datetime

from agentmon.models import DNSEvent, Severity
from agentmon.policies.device_manager import DeviceManager
from agentmon.policies.models import Device, ParentalPolicy, TimeRule
from agentmon.policies.parental_analyzer import ParentalControlAnalyzer


def _make_event(domain: str, client: str, timestamp: datetime) -> DNSEvent:
    """Create a DNS event for testing."""
    return DNSEvent(
        timestamp=timestamp,
        client=client,
        domain=domain,
        query_type="A",
        blocked=False,
    )


def _make_bedtime_analyzer() -> ParentalControlAnalyzer:
    """Create an analyzer with a bedtime rule: Friday 22:00 - 07:00."""
    policy = ParentalPolicy(
        name="bedtime",
        description="Bedtime rule",
        blocked_categories=[],
        time_rules=[
            TimeRule(
                start="22:00",
                end="07:00",
                days=["fri"],
                block_all=True,
            ),
        ],
        alert_severity=Severity.MEDIUM,
    )
    device = Device(
        name="kid-tablet",
        client_ips=["192.168.1.50"],
        policy_names=["bedtime"],
    )
    dm = DeviceManager(devices=[device], policies={"bedtime": policy})
    return ParentalControlAnalyzer(dm)


class TestOvernightTimeRules:
    """Tests for overnight rules that cross midnight."""

    def test_friday_2300_should_match(self) -> None:
        """Friday at 23:00 should be within the Friday 22:00-07:00 window."""
        analyzer = _make_bedtime_analyzer()
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 6, 23, 0),  # Friday 23:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) > 0

    def test_saturday_0300_should_match(self) -> None:
        """Saturday at 03:00 should match the Friday 22:00-07:00 window.

        This is the key bug fix: Saturday is day 5 (not Friday=4), but the
        rule started on Friday and spans midnight, so Saturday early morning
        should still match.
        """
        analyzer = _make_bedtime_analyzer()
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 7, 3, 0),  # Saturday 03:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) > 0

    def test_saturday_0800_should_not_match(self) -> None:
        """Saturday at 08:00 should NOT match Friday 22:00-07:00."""
        analyzer = _make_bedtime_analyzer()
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 7, 8, 0),  # Saturday 08:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) == 0

    def test_thursday_2300_should_not_match(self) -> None:
        """Thursday at 23:00 should NOT match a Friday-only rule."""
        analyzer = _make_bedtime_analyzer()
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 5, 23, 0),  # Thursday 23:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) == 0

    def test_saturday_0000_should_match(self) -> None:
        """Saturday at 00:00 should match the Friday overnight window."""
        analyzer = _make_bedtime_analyzer()
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 7, 0, 0),  # Saturday 00:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) > 0

    def test_sunday_wrap_overnight(self) -> None:
        """Test Sunday overnight rule wrapping to Monday."""
        policy = ParentalPolicy(
            name="sunday-bedtime",
            description="Sunday bedtime",
            blocked_categories=[],
            time_rules=[
                TimeRule(
                    start="21:00",
                    end="06:00",
                    days=["sun"],
                    block_all=True,
                ),
            ],
            alert_severity=Severity.MEDIUM,
        )
        device = Device(
            name="kid-tablet",
            client_ips=["192.168.1.50"],
            policy_names=["sunday-bedtime"],
        )
        dm = DeviceManager(
            devices=[device],
            policies={"sunday-bedtime": policy},
        )
        analyzer = ParentalControlAnalyzer(dm)

        # Monday 02:00 should match Sunday overnight rule
        event = _make_event(
            "youtube.com", "192.168.1.50",
            datetime(2026, 3, 9, 2, 0),  # Monday 02:00
        )
        alerts = analyzer.analyze_event(event)
        assert len(alerts) > 0
