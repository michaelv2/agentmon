"""Connection event analyzer.

Correlates connection events with DNS lookups and detects direct IP access
(connections to public IPs with no prior DNS query from the same client).
"""

import ipaddress
import logging
import socket
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from cachetools import TTLCache

from agentmon.models import Alert, ConnectionEvent, DNSEvent, Severity
from agentmon.storage.db import EventStore

logger = logging.getLogger(__name__)

# Default cache settings
DEFAULT_DNS_CACHE_TTL = 120  # seconds
DEFAULT_DNS_CACHE_SIZE = 10_000
DEFAULT_ALERT_DEDUP_WINDOW = 600  # 10 minutes
DEFAULT_ALERT_CACHE_SIZE = 5000
DEFAULT_REVERSE_CACHE_TTL = 300  # 5 minutes
DEFAULT_REVERSE_CACHE_SIZE = 5000


def reverse_lookup(ip: str) -> str | None:
    """Reverse DNS lookup on an IP address. Returns FQDN or None.

    Kept as a module-level function so tests can easily mock it.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC1918, loopback, or link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


@dataclass
class ConnectionAnalyzerConfig:
    """Configuration for the connection analyzer."""

    learning_mode: bool = False
    dns_cache_ttl: int = DEFAULT_DNS_CACHE_TTL
    alert_dedup_window: int = DEFAULT_ALERT_DEDUP_WINDOW
    alert_severity: Severity = Severity.MEDIUM


class ConnectionAnalyzer:
    """Correlates connection events with DNS lookups and detects direct IP access.

    DNS correlation strategy:
        1. track_dns_answer() caches recent DNS queries per client
        2. For each connection event, do a reverse lookup on dst_ip
        3. If the FQDN matches any recently-queried domain for that client -> correlated
        4. If no match and IP is public -> direct IP access alert
    """

    def __init__(self, store: EventStore, config: ConnectionAnalyzerConfig) -> None:
        self.store = store
        self.config = config

        # Recent DNS queries per client: "client" -> set[domain]
        self._dns_domains: TTLCache[str, set[str]] = TTLCache(
            maxsize=DEFAULT_DNS_CACHE_SIZE,
            ttl=config.dns_cache_ttl,
        )

        # Reverse DNS cache: ip -> hostname | None
        self._reverse_cache: TTLCache[str, str | None] = TTLCache(
            maxsize=DEFAULT_REVERSE_CACHE_SIZE,
            ttl=DEFAULT_REVERSE_CACHE_TTL,
        )

        # Alert deduplication: "client|dst_ip" -> True
        self._alert_cache: TTLCache[str, bool] = TTLCache(
            maxsize=DEFAULT_ALERT_CACHE_SIZE,
            ttl=config.alert_dedup_window,
        )

    def track_dns_answer(self, event: DNSEvent) -> None:
        """Called for each DNS event to populate the per-client domain cache.

        Args:
            event: DNS event to track
        """
        client = event.client
        domain = event.domain.lower()

        if client in self._dns_domains:
            self._dns_domains[client].add(domain)
        else:
            self._dns_domains[client] = {domain}

    def _correlate(self, event: ConnectionEvent) -> str | None:
        """Try to correlate a connection with a recent DNS query.

        Returns the matching domain or None.
        """
        client = event.client
        dst_ip = event.dst_ip

        # Get recent domains for this client
        recent_domains: set[str] | None = self._dns_domains.get(client)
        if not recent_domains:
            return None

        # Reverse lookup on destination IP (cached)
        hostname = self._cached_reverse_lookup(dst_ip)
        if hostname is None:
            return None

        hostname_lower = hostname.lower()

        # Check if any recent DNS query from this client matches
        for domain in recent_domains:
            if hostname_lower == domain or hostname_lower.endswith("." + domain):
                return domain

        return None

    def _cached_reverse_lookup(self, ip: str) -> str | None:
        """Reverse DNS lookup with caching."""
        if ip in self._reverse_cache:
            cached: str | None = self._reverse_cache[ip]
            return cached

        result = reverse_lookup(ip)
        self._reverse_cache[ip] = result
        return result

    def _is_duplicate_alert(self, client: str, dst_ip: str) -> bool:
        """Check if we've already alerted on this (client, dst_ip) recently."""
        cache_key = f"{client}|{dst_ip}"
        if cache_key in self._alert_cache:
            return True
        self._alert_cache[cache_key] = True
        return False

    def analyze_event(
        self, event: ConnectionEvent
    ) -> tuple[ConnectionEvent, list[Alert]]:
        """Correlate connection with DNS and check for direct IP access.

        Returns:
            Tuple of (updated event with dns_domain populated if correlated,
            list of alerts).
        """
        alerts: list[Alert] = []

        # Try DNS correlation
        matched_domain = self._correlate(event)

        # Build updated event if we found a correlation
        if matched_domain:
            event = ConnectionEvent(
                timestamp=event.timestamp,
                client=event.client,
                src_port=event.src_port,
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                protocol=event.protocol,
                bytes_sent=event.bytes_sent,
                bytes_recv=event.bytes_recv,
                duration_seconds=event.duration_seconds,
                dns_domain=matched_domain,
            )
        else:
            # No DNS correlation — check for direct IP access
            if (
                not self.config.learning_mode
                and not _is_private_ip(event.dst_ip)
                and not self._is_duplicate_alert(event.client, event.dst_ip)
            ):
                alert = Alert(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.now(UTC),
                    severity=self.config.alert_severity,
                    title=f"Direct IP access: {event.dst_ip}:{event.dst_port}",
                    description=(
                        f"Client {event.client} connected to {event.dst_ip}:{event.dst_port} "
                        f"({event.protocol}) without a prior DNS lookup"
                    ),
                    source_event_type="connection",
                    client=event.client,
                    dst_ip=event.dst_ip,
                    analyzer="connection.direct_ip",
                    confidence=0.7,
                    tags=["direct_ip", "no_dns"],
                )
                alerts.append(alert)

        return event, alerts
