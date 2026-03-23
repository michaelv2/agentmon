"""DNS baseline analyzer.

Builds a baseline of normal DNS behavior per client and flags anomalies.
"""

import logging
import uuid
from dataclasses import dataclass, field

from cachetools import TTLCache

from agentmon.analyzers.entropy import (
    DEFAULT_TRUSTED_INFRASTRUCTURE,
    is_high_entropy_domain,
    is_trusted_infrastructure,
    looks_like_dga,
)
from agentmon.models import Alert, DNSEvent, Severity
from agentmon.storage.db import EventStore

logger = logging.getLogger(__name__)

# Default alert deduplication settings
DEFAULT_DEDUP_WINDOW = 3600  # 1 hour (raised from 10min to suppress repeat alerts)
DEFAULT_DEDUP_CACHE_SIZE = 5000

# Categories considered "benign" for severity downgrade purposes
BENIGN_CATEGORIES = {"benign", "cdn", "cloud_provider", "api_service"}
NOISE_CATEGORIES = {"advertising", "tracking"}


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

    # Known-good domains to ignore. Supports exact match ("example.com")
    # and wildcard suffix ("*.example.com" matches all subdomains + parent).
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

    # LLM classification settings (uses Ollama, two-tier)
    llm_enabled: bool = False
    llm_triage_model: str = "phi3:3.8b"
    llm_escalation_model: str = "gpt-oss:20b"
    llm_classify_new_domains: bool = True  # Classify new domains with LLM
    llm_classify_alerts: bool = True  # Enrich alerts with LLM analysis
    llm_downgrade_enabled: bool = True  # Downgrade severity based on LLM
    llm_downgrade_confidence: float = 0.8  # Minimum confidence to trust downgrade

    # Alert deduplication: suppress repeated alerts for same (domain, client, type)
    alert_dedup_window: int = DEFAULT_DEDUP_WINDOW  # seconds
    alert_dedup_cache_size: int = DEFAULT_DEDUP_CACHE_SIZE

    # Query frequency threshold: suppress DGA/entropy alerts on domains that
    # have been queried more than dga_min_queries_suppress times by more than
    # dga_min_clients_suppress unique clients.  Genuine DGA domains rarely
    # achieve consistent high-volume queries from many clients.
    dga_min_queries_suppress: int = 50
    dga_min_clients_suppress: int = 5

    # Trusted infrastructure parent domains.  High-entropy subdomains are
    # expected under CDN/cloud providers (Akamai, Apple, CloudFront, etc.)
    # and should not trigger DGA/entropy alerts.
    trusted_infrastructure: set[str] = field(
        default_factory=lambda: set(DEFAULT_TRUSTED_INFRASTRUCTURE)
    )

    # OCSP spike detection: alert when a single client makes an abnormally
    # high number of OCSP queries in one hour.  Normal OCSP is high-volume,
    # but sudden spikes may indicate certificate pinning bypass attempts.
    ocsp_spike_enabled: bool = True
    ocsp_spike_threshold: int = 100  # queries per client per hour
    ocsp_spike_severity: str = "medium"

    # Per-domain query rate spike detection (generalized OCSP spike)
    query_rate_spike_enabled: bool = True
    query_rate_spike_threshold: int = 100  # queries per client per domain per hour
    query_rate_spike_severity: str = "medium"

    # Watched domains: enhanced monitoring for domains that are legitimate
    # but could be abused as C2 fronting or data-exfiltration vectors.
    # Supports exact match and wildcard suffix ("*.doubleclick.net").
    # Watched domains get all normal analysis PLUS:
    #   - LOW alert when a new client queries a watched domain for the first time
    #   - MEDIUM alert when per-client hourly volume exceeds threshold
    watched_domains: list[str] = field(default_factory=list)
    watched_domain_volume_threshold: int = 50  # queries per client per hour


class DNSBaselineAnalyzer:
    """Analyzes DNS events against a learned baseline."""

    def __init__(
        self,
        store: EventStore,
        config: AnalyzerConfig | None = None,
        threat_feed_manager=None,
        vt_client=None,
    ) -> None:
        self.store = store
        self.config = config or AnalyzerConfig()
        self._classifier = None
        self._classifier_available = False
        self._threat_feed_manager = threat_feed_manager
        self._vt_client = vt_client

        # Alert deduplication cache: (domain, client, alert_type) -> True
        self._alert_cache: TTLCache[str, bool] = TTLCache(
            maxsize=self.config.alert_dedup_cache_size,
            ttl=self.config.alert_dedup_window,
        )
        self._dedup_hits = 0

        # Precompute trusted infrastructure frozenset (avoids per-call conversion)
        self._trusted_infra: frozenset[str] = frozenset(
            self.config.trusted_infrastructure
        )

        # OCSP spike detection: per-client per-domain hourly counters
        # Key: domain -> {client: count}
        self._ocsp_hourly_counts: dict[str, dict[str, int]] = {}
        self._ocsp_current_hour: int | None = None

        # Watched domain volume tracking: per-client per-domain hourly counters
        self._watched_hourly_counts: dict[str, dict[str, int]] = {}
        self._watched_current_hour: int | None = None

        # Per-domain query rate spike: per-client per-domain hourly counters
        self._rate_hourly_counts: dict[str, dict[str, int]] = {}
        self._rate_current_hour: int | None = None

        # Initialize LLM classifier if enabled
        if self.config.llm_enabled:
            self._init_classifier()

    def _init_classifier(self) -> None:
        """Initialize the LLM classifier (two-tier via Ollama)."""
        try:
            from agentmon.llm.classifier import DomainClassifier, LLMConfig

            llm_config = LLMConfig(
                triage_model=self.config.llm_triage_model,
                escalation_model=self.config.llm_escalation_model,
            )
            self._classifier = DomainClassifier(llm_config, vt_client=self._vt_client)
            self._classifier_available = self._classifier.available
            if self._classifier_available:
                logger.info(
                    f"LLM classifier ready - triage: {self.config.llm_triage_model}, "
                    f"escalation: {self.config.llm_escalation_model}"
                )
            else:
                logger.warning("Ollama not available - LLM classification disabled")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM classifier: {e}")
            self._classifier_available = False

    def _classify_domain_full(self, event: DNSEvent):
        """Classify a domain using the LLM.

        Returns the full ClassificationResult, or None if unavailable.
        """
        if not self._classifier_available or not self._classifier:
            return None

        try:
            return self._classifier.classify(
                domain=event.domain,
                client=event.client,
                query_type=event.query_type,
                blocked=event.blocked,
            )
        except Exception as e:
            logger.debug(f"LLM classification failed for {event.domain}: {e}")
            return None

    def _enrich_alert_with_llm(self, alert: Alert, event: DNSEvent) -> None:
        """Enrich an alert with LLM classification and adjust severity.

        Single path for all LLM-based alert enrichment:
        - Adds llm_analysis text
        - Upgrades severity for malicious/suspicious classifications
        - Downgrades severity for benign/noise classifications (if enabled)
        """
        if not self.config.llm_classify_alerts or alert.llm_analysis:
            return

        result = self._classify_domain_full(event)
        if not result:
            return

        # Format analysis text
        escalation_note = ""
        if result.escalated and result.triage_category:
            escalation_note = f" [escalated from {result.triage_category}]"
        alert.llm_analysis = (
            f"{result.category.value} (confidence: {result.confidence:.2f})"
            f"{escalation_note}: {result.reasoning}"
        )

        # Adjust severity based on structured category
        category = result.category.value
        original_severity = alert.severity

        # Upgrade for threats
        if category in ("likely_malicious", "dga"):
            alert.severity = Severity.HIGH
            alert.confidence = max(alert.confidence, 0.8)
        elif category == "suspicious":
            alert.severity = Severity.MEDIUM
            alert.confidence = max(alert.confidence, 0.6)
        # Downgrade for benign/noise (requires confidence threshold)
        elif self.config.llm_downgrade_enabled and (
            result.confidence >= self.config.llm_downgrade_confidence
            or result.escalated
        ):
            if category in BENIGN_CATEGORIES:
                alert.severity = Severity.INFO
            elif category in NOISE_CATEGORIES:
                alert.severity = Severity.LOW

        if alert.severity != original_severity:
            _SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            direction = (
                "downgraded"
                if _SEVERITY_ORDER.index(alert.severity) < _SEVERITY_ORDER.index(original_severity)
                else "upgraded"
            )
            alert.description += (
                f" [LLM {direction}: {original_severity.value} → {alert.severity.value}]"
            )
            logger.info(
                f"{direction.title()} {alert.domain}: {original_severity.value} → "
                f"{alert.severity.value} (LLM: {category}, conf={result.confidence:.2f})"
            )

    def _is_duplicate_alert(self, domain: str, client: str, alert_type: str) -> bool:
        """Check if we've already alerted on this (domain, client, type) recently.

        If not a duplicate, marks it so future calls within the TTL window return True.
        """
        cache_key = f"{domain}|{client}|{alert_type}"
        if cache_key in self._alert_cache:
            self._dedup_hits += 1
            logger.debug(f"Dedup: suppressing repeat alert for {domain} ({alert_type})")
            return True
        self._alert_cache[cache_key] = True
        return False

    @property
    def dedup_stats(self) -> dict[str, int]:
        """Return deduplication statistics."""
        return {
            "suppressed": self._dedup_hits,
            "cache_size": len(self._alert_cache),
        }

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

        # Check allowlist (exact match or *.suffix wildcard)
        if self._is_allowlisted(domain_lower):
            self.store.update_domain_baseline(event.client, domain_lower, event.timestamp)
            return []

        # Check 0: Threat intelligence feeds (highest priority)
        threat_alert = self._check_threat_feed(event, domain_lower)
        if threat_alert:
            if not self._is_duplicate_alert(domain_lower, event.client, "threat_feed"):
                self._enrich_alert_with_llm(threat_alert, event)
                alerts.append(threat_alert)

        # Check 1: Known-bad patterns
        bad_alert = self._check_known_bad(event, domain_lower)
        if bad_alert:
            if not self._is_duplicate_alert(domain_lower, event.client, "known_bad"):
                self._enrich_alert_with_llm(bad_alert, event)
                alerts.append(bad_alert)

        # Check 2: DGA detection
        dga_alert = self._check_dga(event, domain_lower)
        if dga_alert:
            if not self._is_duplicate_alert(domain_lower, event.client, "dga"):
                self._enrich_alert_with_llm(dga_alert, event)
                alerts.append(dga_alert)

        # Check 2.5: OCSP volume spike detection
        ocsp_alert = self._check_ocsp_spike(event, domain_lower)
        if ocsp_alert:
            if not self._is_duplicate_alert(domain_lower, event.client, "ocsp_spike"):
                self._enrich_alert_with_llm(ocsp_alert, event)
                alerts.append(ocsp_alert)

        # Check 2.6: Per-domain query rate spike
        rate_alert = self._check_query_rate_spike(event, domain_lower)
        if rate_alert:
            if not self._is_duplicate_alert(domain_lower, event.client, "rate_spike"):
                alerts.append(rate_alert)

        # Check 2.7: Watched domain enhanced monitoring
        watched_alerts = self._check_watched_domain(event, domain_lower)
        alerts.extend(watched_alerts)

        # Check 3: New domain (not in baseline)
        if not self.config.learning_mode:
            new_domain_alert = self._check_new_domain(event, domain_lower)
            if new_domain_alert:
                if not self._is_duplicate_alert(domain_lower, event.client, "new_domain"):
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

    def _is_allowlisted(self, domain: str) -> bool:
        """Check if domain matches the allowlist.

        Supports two formats:
        - Exact match: "example.com" matches only "example.com"
        - Wildcard suffix: "*.example.com" matches any subdomain
          of example.com (e.g. "foo.example.com", "a.b.example.com")
          as well as "example.com" itself.
        """
        for entry in self.config.allowlist:
            if entry.startswith("*."):
                suffix = entry[1:]  # ".example.com"
                parent = entry[2:]  # "example.com"
                if domain == parent or domain.endswith(suffix):
                    return True
            elif domain == entry:
                return True
        return False

    def _check_threat_feed(self, event: DNSEvent, domain_lower: str) -> Alert | None:
        """Check if domain is in external threat intelligence feeds."""
        if not self._threat_feed_manager:
            return None

        feed_match = self._threat_feed_manager.check_domain(domain_lower)
        if feed_match:
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=Severity.HIGH,
                title="Domain in threat intelligence feed",
                description=(
                    f"Client {event.client} queried domain '{event.domain}' "
                    f"which appears in threat intelligence feeds (malware/C2/phishing)"
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.threat_feed",
                confidence=0.90,
                tags=["threat_feed", "external_intel"],
            )
        return None

    @staticmethod
    def _matches_at_label_boundary(domain: str, pattern: str) -> bool:
        """Check if pattern appears at domain label boundaries.

        Start boundary: pattern must begin at position 0 or immediately after
        a dot, preventing partial mid-label matches like 'c2-' inside 'ec2-'.

        End boundary: patterns ending with an alphanumeric character (e.g.,
        'beacon') also require the match to end at a label boundary (before a
        dot or at end of string). This prevents 'beacon' from matching
        'beacons2.gvt2.com'. Patterns ending with a non-alphanumeric character
        (e.g., 'c2-') only require start boundary, acting as label prefixes.
        """
        d = domain.lower()
        p = pattern.lower()
        if not p:
            return False
        require_end_boundary = p[-1].isalnum()
        idx = 0
        while True:
            idx = d.find(p, idx)
            if idx == -1:
                return False
            # Start boundary: at position 0 or after a dot
            if idx == 0 or d[idx - 1] == ".":
                if not require_end_boundary:
                    return True
                # End boundary: at end of string or before a dot
                end_idx = idx + len(p)
                if end_idx >= len(d) or d[end_idx] == ".":
                    return True
            idx += 1

    def _check_known_bad(self, event: DNSEvent, domain_lower: str) -> Alert | None:
        """Check if domain matches known-bad patterns."""
        for pattern in self.config.known_bad_patterns:
            if self._matches_at_label_boundary(domain_lower, pattern):
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

    def _is_suppressed_by_popularity(self, domain_lower: str) -> bool:
        """Check if a domain is well-established (high query volume from many clients).

        Genuine DGA domains rarely achieve consistent high-volume queries from
        many clients.  Suppress alerts for domains that exceed both thresholds.
        """
        total_queries, unique_clients = self.store.get_domain_popularity(domain_lower)
        if (total_queries >= self.config.dga_min_queries_suppress
                and unique_clients >= self.config.dga_min_clients_suppress):
            logger.debug(
                "DGA/entropy suppressed for popular domain: %s "
                "(%d queries, %d clients)",
                domain_lower, total_queries, unique_clients,
            )
            return True
        return False

    def _check_dga(self, event: DNSEvent, domain_lower: str) -> Alert | None:
        """Check if domain looks like DGA output."""
        is_dga, reasons = looks_like_dga(domain_lower)

        if is_dga:
            # Suppress for trusted CDN/infrastructure parents
            if is_trusted_infrastructure(domain_lower, self._trusted_infra):
                logger.debug(
                    "DGA suppressed for trusted infrastructure: %s", domain_lower
                )
                return None

            # Suppress for well-established domains (many clients, high volume)
            if self._is_suppressed_by_popularity(domain_lower):
                return None

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
            # Same suppression checks for standalone entropy alerts
            if is_trusted_infrastructure(domain_lower, self._trusted_infra):
                logger.debug(
                    "Entropy alert suppressed for trusted infrastructure: %s",
                    domain_lower,
                )
                return None

            if self._is_suppressed_by_popularity(domain_lower):
                return None

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

    def _check_ocsp_spike(self, event: DNSEvent, domain_lower: str) -> Alert | None:
        """Check for OCSP query volume spikes from a single client.

        Normal OCSP traffic is high-volume, but a sudden spike from one client
        may indicate certificate pinning bypass attempts.  Tracks per-client
        per-domain query counts within each clock hour and fires once when
        the threshold is reached.
        """
        if not self.config.ocsp_spike_enabled:
            return None

        # Only track domains whose first label starts with "ocsp"
        first_label = domain_lower.split(".")[0]
        if not first_label.startswith("ocsp"):
            return None

        # Reset counters on hour boundary (based on event time, not wall clock)
        current_hour = event.timestamp.hour
        if self._ocsp_current_hour != current_hour:
            self._ocsp_hourly_counts.clear()
            self._ocsp_current_hour = current_hour

        # Increment counter
        if domain_lower not in self._ocsp_hourly_counts:
            self._ocsp_hourly_counts[domain_lower] = {}
        client_counts = self._ocsp_hourly_counts[domain_lower]
        client_counts[event.client] = client_counts.get(event.client, 0) + 1

        count = client_counts[event.client]
        # Alert exactly once when threshold is crossed
        if count == self.config.ocsp_spike_threshold:
            try:
                severity = Severity(self.config.ocsp_spike_severity)
            except ValueError:
                severity = Severity.MEDIUM
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=severity,
                title=f"OCSP query spike: {event.domain}",
                description=(
                    f"Client {event.client} made {count} OCSP queries to "
                    f"'{event.domain}' in the current hour "
                    f"(threshold: {self.config.ocsp_spike_threshold}). "
                    f"Sudden OCSP spikes may indicate certificate pinning "
                    f"bypass attempts."
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.ocsp_spike",
                confidence=0.4,
                tags=["ocsp", "volume_spike"],
            )

        return None

    def _check_query_rate_spike(
        self, event: DNSEvent, domain_lower: str,
    ) -> Alert | None:
        """Check for per-domain query rate spikes from a single client.

        Generalized form of OCSP spike detection: any client+domain pair
        exceeding the hourly threshold fires an alert.  Catches beaconing,
        DNS tunneling, runaway resolvers, and forwarding loops.
        """
        if not self.config.query_rate_spike_enabled:
            return None

        # Reset counters on hour boundary (based on event time)
        current_hour = event.timestamp.hour
        if self._rate_current_hour != current_hour:
            self._rate_hourly_counts.clear()
            self._rate_current_hour = current_hour

        # Increment counter
        if domain_lower not in self._rate_hourly_counts:
            self._rate_hourly_counts[domain_lower] = {}
        client_counts = self._rate_hourly_counts[domain_lower]
        client_counts[event.client] = client_counts.get(event.client, 0) + 1

        count = client_counts[event.client]
        # Alert exactly once when threshold is crossed
        if count == self.config.query_rate_spike_threshold:
            try:
                severity = Severity(self.config.query_rate_spike_severity)
            except ValueError:
                severity = Severity.MEDIUM
            return Alert(
                id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                severity=severity,
                title=f"Query rate spike: {event.domain}",
                description=(
                    f"Client {event.client} queried '{event.domain}' "
                    f"{count} times in the current hour "
                    f"(threshold: {self.config.query_rate_spike_threshold}). "
                    f"High per-domain query rates may indicate beaconing, "
                    f"DNS tunneling, or a forwarding loop."
                ),
                source_event_type="dns",
                client=event.client,
                domain=event.domain,
                analyzer="dns_baseline.query_rate_spike",
                confidence=0.4,
                tags=["volume_spike", "rate_anomaly"],
            )

        return None

    def _is_watched(self, domain: str) -> bool:
        """Check if domain matches the watched domains list.

        Same matching semantics as the allowlist: exact match or wildcard
        suffix ("*.example.com" matches subdomains and the parent).
        """
        for entry in self.config.watched_domains:
            if entry.startswith("*."):
                suffix = entry[1:]  # ".doubleclick.net"
                parent = entry[2:]  # "doubleclick.net"
                if domain == parent or domain.endswith(suffix):
                    return True
            elif domain == entry:
                return True
        return False

    def _check_watched_domain(
        self, event: DNSEvent, domain_lower: str,
    ) -> list[Alert]:
        """Enhanced monitoring for watched domains.

        Watched domains are legitimate services that could be abused as C2
        fronting or data-exfiltration vectors (e.g., doubleclick.net, Google
        infrastructure).  They receive all normal analysis plus:

        1. First-query alert when a new client queries a watched domain
        2. Volume spike alert when per-client hourly count exceeds threshold
        """
        if not self.config.watched_domains or not self._is_watched(domain_lower):
            return []

        alerts: list[Alert] = []

        # --- First-query detection ---
        if not self.store.is_domain_known(event.client, domain_lower):
            if not self._is_duplicate_alert(
                domain_lower, event.client, "watched_first",
            ):
                alerts.append(Alert(
                    id=str(uuid.uuid4()),
                    timestamp=event.timestamp,
                    severity=Severity.LOW,
                    title=f"Watched domain first query: {event.domain}",
                    description=(
                        f"Client {event.client} queried watched domain "
                        f"'{event.domain}' for the first time. This domain "
                        f"is under enhanced monitoring for potential abuse."
                    ),
                    source_event_type="dns",
                    client=event.client,
                    domain=event.domain,
                    analyzer="dns_baseline.watched_domain",
                    confidence=0.3,
                    tags=["watched", "first_query"],
                ))

        # --- Per-client hourly volume tracking ---
        current_hour = event.timestamp.hour
        if self._watched_current_hour != current_hour:
            self._watched_hourly_counts.clear()
            self._watched_current_hour = current_hour

        if domain_lower not in self._watched_hourly_counts:
            self._watched_hourly_counts[domain_lower] = {}
        client_counts = self._watched_hourly_counts[domain_lower]
        client_counts[event.client] = client_counts.get(event.client, 0) + 1

        count = client_counts[event.client]
        if count == self.config.watched_domain_volume_threshold:
            if not self._is_duplicate_alert(
                domain_lower, event.client, "watched_volume",
            ):
                alerts.append(Alert(
                    id=str(uuid.uuid4()),
                    timestamp=event.timestamp,
                    severity=Severity.MEDIUM,
                    title=f"Watched domain volume spike: {event.domain}",
                    description=(
                        f"Client {event.client} made {count} queries to "
                        f"watched domain '{event.domain}' in the current "
                        f"hour (threshold: "
                        f"{self.config.watched_domain_volume_threshold}). "
                        f"This domain is under enhanced monitoring for "
                        f"potential abuse."
                    ),
                    source_event_type="dns",
                    client=event.client,
                    domain=event.domain,
                    analyzer="dns_baseline.watched_volume",
                    confidence=0.5,
                    tags=["watched", "volume_spike"],
                ))

        return alerts

    def _check_new_domain(self, event: DNSEvent, domain_lower: str) -> Alert | None:
        """Check if this is a never-before-seen domain for this client.

        Suppressed for globally popular domains (already queried by many
        clients) — these are clearly not suspicious when a new client queries
        them. Uses the same popularity thresholds as DGA suppression.

        New-domain alerts are INFO severity and are NOT enriched with LLM
        classification. The long tail of DNS means most new domains are
        benign, and classifying each one burns LLM/VT quota for little value.
        """
        if not self.store.is_domain_known(event.client, domain_lower):
            # Suppress for well-known domains (same thresholds as DGA suppression)
            total_queries, unique_clients = self.store.get_domain_popularity(domain_lower)
            if (total_queries >= self.config.dga_min_queries_suppress
                    and unique_clients >= self.config.dga_min_clients_suppress):
                return None

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

    def get_baseline_stats(self, client: str | None = None) -> dict:
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
