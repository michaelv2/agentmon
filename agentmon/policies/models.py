"""Data models for parental control policies."""

from dataclasses import dataclass, field
from typing import Optional

from agentmon.models import Severity


@dataclass
class TimeRule:
    """Defines a time window when restrictions apply.

    Attributes:
        start: Start time in HH:MM format (24-hour)
        end: End time in HH:MM format (24-hour)
        days: List of abbreviated day names (mon, tue, wed, thu, fri, sat, sun)
        allowed_categories: If set, ONLY these categories are allowed during this window
    """

    start: str  # "15:00"
    end: str  # "17:00"
    days: list[str]  # ["mon", "tue", "wed", "thu", "fri"]
    allowed_categories: Optional[list[str]] = None


@dataclass
class ParentalPolicy:
    """Policy defining access restrictions for a device group.

    Attributes:
        name: Policy identifier (e.g., "homework", "after-school")
        description: Human-readable description
        blocked_categories: Categories that are always blocked
        allowed_domains: Whitelist of always-allowed domains (exact or suffix match)
        time_rules: Time-based restriction windows
        alert_severity: Severity level for alerts from this policy
    """

    name: str
    description: str
    blocked_categories: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    time_rules: list[TimeRule] = field(default_factory=list)
    alert_severity: Severity = Severity.MEDIUM


@dataclass
class Device:
    """Maps a device to a policy.

    Attributes:
        name: Human-readable device name (e.g., "alice-laptop")
        client_ips: List of IP addresses associated with this device
        policy_name: Name of the policy to apply
    """

    name: str
    client_ips: list[str]
    policy_name: str
