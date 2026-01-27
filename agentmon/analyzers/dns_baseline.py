"""DNS baseline analyzer.

Builds a baseline of normal DNS behavior per client and flags anomalies.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from agentmon.models import DNSEvent, Alert, Severity
from agentmon.storage.db import EventStore
from agentmon.analyzers.entropy import looks_like_dga, is_high_entropy_domain


@dataclass
class AnalyzerConfig:
    """Configuration for the DNS baseline analyzer."""

    # Entropy thresholds
    entropy_threshold: float = 3.5
    entropy_min_length: int = 10

    # Baseline settings
    learning_mode: bool = False  # If True, only build baseline, don't alert

    # Known-bad domain patterns (substrings to match)
    known_bad_patterns: list[str] = field(default_factory=list)

    # Known-good domains to ignore (exact match after lowercasing)
    allowlist: set[str] = field(default_factory=set)

    # Domain suffixes to always ignore (e.g., local domains)
    ignore_suffixes: list[str] = field(default_factory=lambda: [
        ".local",
        ".lan",
        ".home",
        ".internal",
        ".localdomain",
        ".arpa",  # Reverse DNS
    ])


class DNSBaselineAnalyzer:
    """Analyzes DNS events against a learned baseline."""

    def __init__(self, store: EventStore, config: Optional[AnalyzerConfig] = None) -> None:
        self.store = store
        self.config = config or AnalyzerConfig()

    def analyze_event(self, event: DNSEvent) -> list[Alert]:
        """Analyze a single DNS event and return any alerts.

        Args:
            event: The DNS event to analyze

        Returns:
            List of alerts (may be empty)
        """
        alerts: list[Alert] = []
        domain_lower = event.domain.lower()

        # Skip ignored domains
        if self._should_ignore(domain_lower):
            # Still update baseline for ignored domains
            self.store.update_domain_baseline(event.client, domain_lower, event.timestamp)
            return []

        # Check allowlist
        if domain_lower in self.config.allowlist:
            self.store.update_domain_baseline(event.client, domain_lower, event.timestamp)
            return []

        # Check 1: Known-bad patterns
        bad_alert = self._check_known_bad(event, domain_lower)
        if bad_alert:
            alerts.append(bad_alert)

        # Check 2: DGA detection
        dga_alert = self._check_dga(event, domain_lower)
        if dga_alert:
            alerts.append(dga_alert)

        # Check 3: New domain (not in baseline)
        if not self.config.learning_mode:
            new_domain_alert = self._check_new_domain(event, domain_lower)
            if new_domain_alert:
                alerts.append(new_domain_alert)

        # Always update baseline (after checks, so we can detect "new")
        self.store.update_domain_baseline(event.client, domain_lower, event.timestamp)

        return alerts

    def analyze_batch(self, events: list[DNSEvent]) -> list[Alert]:
        """Analyze a batch of DNS events.

        Args:
            events: List of DNS events to analyze

        Returns:
            List of all alerts generated
        """
        all_alerts: list[Alert] = []
        for event in events:
            alerts = self.analyze_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def _should_ignore(self, domain: str) -> bool:
        """Check if domain should be ignored based on suffix."""
        return any(domain.endswith(suffix) for suffix in self.config.ignore_suffixes)

    def _check_known_bad(self, event: DNSEvent, domain_lower: str) -> Optional[Alert]:
        """Check if domain matches known-bad patterns."""
        for pattern in self.config.known_bad_patterns:
            if pattern.lower() in domain_lower:
                return Alert(
                    id=str(uuid.uuid4()),
                    timestamp=event.timestamp,
                    severity=Severity.HIGH,
                    title=f"Known-bad domain pattern: {pattern}",
                    description=(
                        f"Client {event.client} queried domain '{event.domain}' "
                        f"which matches known-bad pattern '{pattern}'"
                    ),
                    source_event_type="dns",
                    client=event.client,
                    domain=event.domain,
                    analyzer="dns_baseline.known_bad",
                    confidence=0.95,
                )
        return None

    def _check_dga(self, event: DNSEvent, domain_lower: str) -> Optional[Alert]:
        """Check if domain looks like DGA output."""
        is_dga, reasons = looks_like_dga(domain_lower)

        if is_dga:
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=Severity.MEDIUM,
                title="Potential DGA domain detected",
                description=(
                    f"Client {event.client} queried domain '{event.domain}' "
                    f"which has DGA-like characteristics: {', '.join(reasons)}"
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.dga",
                confidence=0.7,
                tags=["dga", "entropy"],
            )

        # Also check just high entropy (even if not full DGA match)
        is_high_ent, entropy = is_high_entropy_domain(
            domain_lower,
            threshold=self.config.entropy_threshold,
            min_length=self.config.entropy_min_length,
        )

        if is_high_ent and not is_dga:  # Don't double-alert
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=Severity.LOW,
                title="High-entropy domain",
                description=(
                    f"Client {event.client} queried domain '{event.domain}' "
                    f"with entropy {entropy:.2f} (threshold: {self.config.entropy_threshold})"
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.entropy",
                confidence=0.5,
                tags=["entropy"],
            )

        return None

    def _check_new_domain(self, event: DNSEvent, domain_lower: str) -> Optional[Alert]:
        """Check if this is a never-before-seen domain for this client."""
        if not self.store.is_domain_known(event.client, domain_lower):
            # This is a new domain - could be suspicious
            # We generate a low-severity alert that can be reviewed
            # In practice, you'd want more context (time of day, query volume, etc.)
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=Severity.INFO,
                title="New domain observed",
                description=(
                    f"Client {event.client} queried new domain '{event.domain}' "
                    f"for the first time"
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.new_domain",
                confidence=0.3,
                tags=["new", "baseline"],
            )

        return None

    def get_baseline_stats(self, client: Optional[str] = None) -> dict:
        """Get statistics about the current baseline.

        Args:
            client: Optional client to filter by

        Returns:
            Dictionary with baseline statistics
        """
        if client:
            result = self.store.conn.execute("""
                SELECT
                    COUNT(*) as total_domains,
                    MIN(first_seen) as earliest,
                    MAX(last_seen) as latest,
                    SUM(query_count) as total_queries
                FROM domain_baseline
                WHERE client = ?
            """, [client]).fetchone()
        else:
            result = self.store.conn.execute("""
                SELECT
                    COUNT(*) as total_domains,
                    COUNT(DISTINCT client) as total_clients,
                    MIN(first_seen) as earliest,
                    MAX(last_seen) as latest,
                    SUM(query_count) as total_queries
                FROM domain_baseline
            """).fetchone()

        if result is None:
            return {}

        if client:
            return {
                "client": client,
                "total_domains": result[0],
                "earliest": result[1],
                "latest": result[2],
                "total_queries": result[3],
            }
        else:
            return {
                "total_domains": result[0],
                "total_clients": result[1],
                "earliest": result[2],
                "latest": result[3],
                "total_queries": result[4],
            }
