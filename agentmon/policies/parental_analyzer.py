"""Parental control analyzer for DNS events.

Evaluates DNS events against per-device policies and time-based rules
to generate alerts when children access restricted content.
"""

import logging
import uuid
from datetime import datetime

from agentmon.models import Alert, DNSEvent, Severity
from agentmon.policies.category_classifier import classify_domain
from agentmon.policies.device_manager import DeviceManager
from agentmon.policies.models import Device, ParentalPolicy, TimeRule

logger = logging.getLogger(__name__)

# Map day abbreviations to weekday numbers (Monday=0)
DAY_MAP = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


class ParentalControlAnalyzer:
    """Analyzes DNS events against parental control policies.

    For each DNS event:
    1. Look up device by client IP
    2. Get associated policy
    3. Check if domain is whitelisted
    4. Check if we're in a restricted time window
    5. Categorize domain and check against blocked categories
    6. Generate alerts as appropriate
    """

    def __init__(self, device_manager: DeviceManager) -> None:
        """Initialize analyzer.

        Args:
            device_manager: Manages device-to-policy mappings
        """
        self.device_manager = device_manager

    def analyze_event(self, event: DNSEvent) -> list[Alert]:
        """Analyze a DNS event against parental policies.

        Args:
            event: DNS event to analyze

        Returns:
            List of alerts (empty if no policy violations)
        """
        # Look up device and policy
        result = self.device_manager.get_policy(event.client)
        if not result:
            return []  # No policy for this client

        device, policy = result
        category = classify_domain(event.domain)

        # Check whitelist first (exact match or suffix match)
        if self._is_whitelisted(event.domain, policy.allowed_domains):
            return []

        # Check if we're in a time-restricted window
        active_rule = self._get_active_time_rule(policy, event.timestamp)

        if active_rule:
            # During restricted hours
            if active_rule.allowed_categories is not None:
                # Strict mode: only allowed_categories permitted
                if category not in active_rule.allowed_categories:
                    if category == "unknown":
                        return [
                            self._create_alert(
                                event,
                                device,
                                policy,
                                category,
                                "Unknown domain during restricted hours - whitelist if legitimate",
                            )
                        ]
                    else:
                        return [
                            self._create_alert(
                                event,
                                device,
                                policy,
                                category,
                                f"Category '{category}' not in allowed list during restricted hours",
                            )
                        ]
            else:
                # Block mode: blocked_categories are denied
                if category in policy.blocked_categories:
                    return [
                        self._create_alert(
                            event,
                            device,
                            policy,
                            category,
                            f"Category '{category}' blocked during restricted hours",
                        )
                    ]
                elif category == "unknown":
                    # Alert on unknown domains during restricted hours
                    return [
                        self._create_alert(
                            event,
                            device,
                            policy,
                            category,
                            "Unknown domain during restricted hours - whitelist if legitimate",
                        )
                    ]

        # Outside restricted hours: no alerts for parental controls
        # (Security analyzer still runs separately)
        return []

    def _is_whitelisted(self, domain: str, allowed_domains: list[str]) -> bool:
        """Check if domain is on the whitelist.

        Supports exact match and suffix match (e.g., "wikipedia.org" matches
        "en.wikipedia.org").

        Args:
            domain: Domain to check
            allowed_domains: List of allowed domains

        Returns:
            True if domain is whitelisted
        """
        domain_lower = domain.lower()

        for allowed in allowed_domains:
            allowed_lower = allowed.lower()
            # Exact match
            if domain_lower == allowed_lower:
                return True
            # Suffix match (subdomain of allowed domain)
            if domain_lower.endswith("." + allowed_lower):
                return True

        return False

    def _get_active_time_rule(
        self,
        policy: ParentalPolicy,
        timestamp: datetime,
    ) -> TimeRule | None:
        """Check if any time rule is active for the given timestamp.

        Args:
            policy: Policy to check
            timestamp: Event timestamp

        Returns:
            Active TimeRule if we're in a restricted window, None otherwise
        """
        weekday = timestamp.weekday()  # Monday=0, Sunday=6
        current_time = timestamp.strftime("%H:%M")

        for rule in policy.time_rules:
            # Check if today is in the rule's days
            rule_days = [DAY_MAP.get(d.lower(), -1) for d in rule.days]
            if weekday not in rule_days:
                continue

            # Check if current time is within the rule's window
            if rule.start <= current_time <= rule.end:
                return rule

        return None

    def _create_alert(
        self,
        event: DNSEvent,
        device: Device,
        policy: ParentalPolicy,
        category: str,
        reason: str,
    ) -> Alert:
        """Create a parental control alert.

        Args:
            event: DNS event that triggered the alert
            device: Device that made the request
            policy: Policy that was violated
            category: Category of the domain
            reason: Human-readable reason for the alert

        Returns:
            Alert object
        """
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=event.timestamp,
            severity=policy.alert_severity,
            title=f"Parental control: {reason}",
            description=(
                f"Device '{device.name}' accessed {event.domain} "
                f"(category: {category}) during policy '{policy.name}' "
                f"restricted hours. {reason}"
            ),
            source_event_type="dns",
            client=event.client,
            domain=event.domain,
            analyzer="parental_control",
            confidence=1.0,
            tags=["parental", category, policy.name],
        )
