"""Client Identity Resolution for agentmon.

Resolves client IP addresses to stable hostnames so that baselines survive
DHCP changes. Uses reverse DNS with caching and explicit config mappings.

Fallback chain:
1. Explicit config mapping (highest priority)
2. Reverse DNS (PTR) lookup against local DNS
3. Raw IP address (fallback for devices without PTR records)
"""

import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ResolverConfig:
    """Configuration for client identity resolution."""

    # Enable/disable resolution (if disabled, IPs are used as-is)
    enabled: bool = False

    # DNS server for reverse lookups (usually Pi-hole or local router)
    # If None, uses system default resolver
    dns_server: Optional[str] = None

    # Cache TTL for resolved hostnames (seconds)
    cache_ttl: int = 3600  # 1 hour

    # Strip domain suffix from hostnames
    # "alice-laptop.lan" → "alice-laptop"
    strip_suffix: bool = True

    # Explicit IP -> hostname mappings (highest priority)
    # Use for devices that don't register hostnames via DHCP
    mappings: dict[str, str] = field(default_factory=dict)


class ClientResolver:
    """Resolves client IPs to stable hostnames.

    This allows baselines to survive DHCP changes by using the device's
    hostname instead of its IP address for tracking.

    Usage:
        resolver = ClientResolver(config)
        hostname = resolver.resolve("192.168.1.50")  # Returns "alice-laptop"
    """

    def __init__(self, config: ResolverConfig):
        self.config = config
        self._cache: dict[str, tuple[str, datetime]] = {}  # ip -> (hostname, expires)
        self._failed_cache: dict[str, datetime] = {}  # ip -> failed_until (negative cache)
        self._negative_cache_ttl = 300  # 5 minutes for failed lookups

    def resolve(self, ip: str) -> str:
        """Resolve IP to hostname. Returns IP if resolution fails or is disabled.

        Args:
            ip: IP address to resolve

        Returns:
            Hostname if found, otherwise the original IP
        """
        if not self.config.enabled:
            return ip

        # 1. Check explicit mappings first (highest priority)
        if ip in self.config.mappings:
            return self.config.mappings[ip]

        # 2. Check positive cache
        if ip in self._cache:
            hostname, expires = self._cache[ip]
            if datetime.now() < expires:
                return hostname
            else:
                # Cache expired, remove it
                del self._cache[ip]

        # 3. Check negative cache (avoid hammering DNS for unknown IPs)
        if ip in self._failed_cache:
            failed_until = self._failed_cache[ip]
            if datetime.now() < failed_until:
                return ip  # Still in negative cache, return IP
            else:
                # Negative cache expired, allow retry
                del self._failed_cache[ip]

        # 4. Reverse DNS lookup
        hostname = self._reverse_lookup(ip)
        if hostname:
            # Cache successful lookups
            expires = datetime.now() + timedelta(seconds=self.config.cache_ttl)
            self._cache[ip] = (hostname, expires)
            logger.debug(f"Resolved {ip} → {hostname}")
            return hostname

        # 5. Cache failed lookup and fallback to IP
        self._failed_cache[ip] = datetime.now() + timedelta(seconds=self._negative_cache_ttl)
        return ip

    def _reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform PTR lookup for IP address.

        Args:
            ip: IP address to look up

        Returns:
            Hostname if found, None otherwise
        """
        try:
            # Use gethostbyaddr for reverse DNS lookup
            # This respects /etc/hosts and NSS configuration
            hostname, _, _ = socket.gethostbyaddr(ip)

            if self.config.strip_suffix:
                # "alice-laptop.lan" → "alice-laptop"
                # "server.home.local" → "server"
                hostname = hostname.split('.')[0]

            return hostname

        except socket.herror:
            # No PTR record found - this is expected for many devices
            logger.debug(f"No PTR record for {ip}")
            return None
        except socket.gaierror as e:
            # DNS resolution failed (network issue, invalid IP, etc.)
            logger.debug(f"DNS lookup failed for {ip}: {e}")
            return None
        except Exception as e:
            # Unexpected error
            logger.warning(f"Unexpected error resolving {ip}: {e}")
            return None

    def clear_cache(self) -> None:
        """Clear both positive and negative caches."""
        self._cache.clear()
        self._failed_cache.clear()
        logger.debug("Resolver cache cleared")

    def get_cache_stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dict with cache size and hit rate information
        """
        now = datetime.now()

        # Count valid entries
        valid_positive = sum(1 for _, (_, exp) in self._cache.items() if exp > now)
        valid_negative = sum(1 for _, exp in self._failed_cache.items() if exp > now)

        return {
            "positive_entries": valid_positive,
            "negative_entries": valid_negative,
            "explicit_mappings": len(self.config.mappings),
        }

    def add_mapping(self, ip: str, hostname: str) -> None:
        """Add an explicit IP -> hostname mapping at runtime.

        Args:
            ip: IP address
            hostname: Hostname to map to
        """
        self.config.mappings[ip] = hostname
        # Also add to positive cache
        expires = datetime.now() + timedelta(seconds=self.config.cache_ttl)
        self._cache[ip] = (hostname, expires)
        logger.debug(f"Added explicit mapping: {ip} → {hostname}")
