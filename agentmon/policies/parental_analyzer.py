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
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

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

        Evaluates the event against all policies assigned to the device.
        Each policy is checked independently; most-restrictive-wins semantics
        apply (any policy can trigger an alert). Alerts are deduplicated by
        policy name.

        Args:
            event: DNS event to analyze

        Returns:
            List of alerts (empty if no policy violations)
        """
        result = self.device_manager.get_policies(event.client)
        if not result:
            return []

        device, policies = result
        category = classify_domain(event.domain)
        alerts: list[Alert] = []
        seen_policies: set[str] = set()

        for policy in policies:
            # Check whitelist: if this policy whitelists the domain, skip it
            if self._is_whitelisted(event.domain, policy.allowed_domains):
                continue

            active_rule = self._get_active_time_rule(policy, event.timestamp)
            if not active_rule:
                continue

            alert = self._evaluate_rule(event, device, policy, category, active_rule)
            if alert and policy.name not in seen_policies:
                seen_policies.add(policy.name)
                alerts.append(alert)

        # Use highest severity across all triggered alerts
        if len(alerts) > 1:
            max_severity = max(
                (a.severity for a in alerts),
                key=lambda s: _SEVERITY_ORDER.get(s, 0),
            )
            alerts = [
                Alert(
                    id=a.id,
                    timestamp=a.timestamp,
                    severity=max_severity,
                    title=a.title,
                    description=a.description,
                    source_event_type=a.source_event_type,
                    client=a.client,
                    domain=a.domain,
                    analyzer=a.analyzer,
                    confidence=a.confidence,
                    tags=a.tags,
                )
                for a in alerts
            ]

        return alerts

    def _evaluate_rule(
        self,
        event: DNSEvent,
        device: Device,
        policy: ParentalPolicy,
        category: str,
        active_rule: TimeRule,
    ) -> Alert | None:
        """Evaluate a single time rule against an event.

        Args:
            event: DNS event to evaluate
            device: Device that made the request
            policy: Policy being evaluated
            category: Classified category of the domain
            active_rule: The active time rule to evaluate against

        Returns:
            Alert if the rule is violated, None otherwise
        """
        # Block-all mode: alert on ANY DNS activity during this window
        if active_rule.block_all:
            return self._create_alert(
                event, device, policy, category,
                "Device active during downtime hours",
            )

        # During restricted hours
        if active_rule.allowed_categories is not None:
            # Strict mode: only allowed_categories permitted
            if category not in active_rule.allowed_categories:
                if category == "unknown":
                    return self._create_alert(
                        event, device, policy, category,
                        "Unknown domain during restricted hours - whitelist if legitimate",
                    )
                return self._create_alert(
                    event, device, policy, category,
                    f"Category '{category}' not in allowed list during restricted hours",
                )
        else:
            # Block mode: blocked_categories are denied
            if category in policy.blocked_categories:
                return self._create_alert(
                    event, device, policy, category,
                    f"Category '{category}' blocked during restricted hours",
                )
            if category == "unknown":
                return self._create_alert(
                    event, device, policy, category,
                    "Unknown domain during restricted hours - whitelist if legitimate",
                )

        return None

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

        For overnight rules (start > end, e.g. 22:00-07:00), we check two cases:
        1. Current time >= start and today's weekday is in rule_days (before midnight)
        2. Current time <= end and *yesterday's* weekday is in rule_days (after midnight)

        Args:
            policy: Policy to check
            timestamp: Event timestamp

        Returns:
            Active TimeRule if we're in a restricted window, None otherwise
        """
        weekday = timestamp.weekday()  # Monday=0, Sunday=6
        prev_weekday = (weekday - 1) % 7
        current_time = timestamp.strftime("%H:%M")

        for rule in policy.time_rules:
            rule_days = [DAY_MAP.get(d.lower(), -1) for d in rule.days]

            if rule.start <= rule.end:
                # Same-day window: e.g. 15:00-17:00
                if weekday in rule_days and rule.start <= current_time <= rule.end:
                    return rule
            else:
                # Overnight window: e.g. 22:00-07:00
                # Before midnight: today must be in rule_days
                if weekday in rule_days and current_time >= rule.start:
                    return rule
                # After midnight: yesterday must be in rule_days
                if prev_weekday in rule_days and current_time <= rule.end:
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
