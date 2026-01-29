"""VirusTotal threat intelligence API integration.

Queries VirusTotal for real-time domain reputation and vendor detections.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import requests
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# VirusTotal API endpoint
VT_API_URL = "https://www.virustotal.com/api/v3/domains"

# Default cache: 24 hours
DEFAULT_VT_CACHE_TTL = 86400


@dataclass
class VirusTotalReputation:
    """Reputation data from VirusTotal."""

    domain: str
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    harmless_count: int = 0
    last_analysis_date: Optional[datetime] = None
    last_analysis_stats: Optional[dict] = None

    @property
    def total_vendors(self) -> int:
        """Total number of vendors that analyzed this domain."""
        return (
            self.malicious_count
            + self.suspicious_count
            + self.undetected_count
            + self.harmless_count
        )

    @property
    def risk_score(self) -> float:
        """Calculate risk score (0-1)."""
        if self.total_vendors == 0:
            return 0.0
        # Weight malicious higher than suspicious
        risk = (self.malicious_count * 1.0 + self.suspicious_count * 0.5) / self.total_vendors
        return min(1.0, risk)

    @property
    def is_high_risk(self) -> bool:
        """Check if domain is considered high risk."""
        return self.malicious_count >= 3 or self.risk_score >= 0.5

    def summary(self) -> str:
        """Human-readable summary."""
        if self.total_vendors == 0:
            return "No vendors analyzed this domain"
        return (
            f"VirusTotal: {self.malicious_count} malicious, "
            f"{self.suspicious_count} suspicious, {self.harmless_count} harmless "
            f"({self.total_vendors} vendors)"
        )


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl: int = DEFAULT_VT_CACHE_TTL,
        timeout: int = 10,
    ) -> None:
        """Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (None to disable)
            cache_ttl: Cache duration in seconds
            timeout: HTTP request timeout
        """
        self.api_key = api_key
        self.timeout = timeout
        self.available = api_key is not None

        # Cache: domain -> VirusTotalReputation
        self._cache: TTLCache = TTLCache(maxsize=1000, ttl=cache_ttl)

        if self.api_key:
            logger.info("VirusTotal API enabled")
        else:
            logger.debug("VirusTotal API disabled (no API key)")

    def lookup(self, domain: str) -> Optional[VirusTotalReputation]:
        """Look up domain reputation on VirusTotal.

        Args:
            domain: Domain name to check

        Returns:
            VirusTotalReputation if found, None if API unavailable or lookup fails
        """
        if not self.available:
            return None

        domain_lower = domain.lower()

        # Check cache
        if domain_lower in self._cache:
            logger.debug(f"VirusTotal cache hit: {domain}")
            return self._cache[domain_lower]

        # Query API
        try:
            reputation = self._query_api(domain_lower)
            if reputation:
                self._cache[domain_lower] = reputation
            return reputation
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for {domain}: {e}")
            return None

    def _query_api(self, domain: str) -> Optional[VirusTotalReputation]:
        """Query VirusTotal API for domain reputation.

        Args:
            domain: Domain name to query

        Returns:
            VirusTotalReputation or None if request fails
        """
        headers = {"x-apikey": self.api_key}

        try:
            resp = requests.get(
                f"{VT_API_URL}/{domain}",
                headers=headers,
                timeout=self.timeout,
            )

            if resp.status_code == 404:
                # Domain not found in VT (not analyzed yet)
                logger.debug(f"Domain not yet in VirusTotal: {domain}")
                return VirusTotalReputation(domain=domain)

            resp.raise_for_status()

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})

            # Parse last analysis date
            last_analysis_date = None
            if "last_analysis_date" in attrs:
                try:
                    last_analysis_date = datetime.fromtimestamp(
                        attrs["last_analysis_date"]
                    )
                except (TypeError, ValueError):
                    pass

            reputation = VirusTotalReputation(
                domain=domain,
                malicious_count=last_analysis.get("malicious", 0),
                suspicious_count=last_analysis.get("suspicious", 0),
                undetected_count=last_analysis.get("undetected", 0),
                harmless_count=last_analysis.get("harmless", 0),
                last_analysis_date=last_analysis_date,
                last_analysis_stats=last_analysis,
            )

            logger.debug(f"VirusTotal lookup: {domain} - {reputation.summary()}")
            return reputation

        except requests.RequestException as e:
            logger.warning(f"VirusTotal API error: {e}")
            return None

    def get_stats(self) -> dict:
        """Get client statistics."""
        return {
            "available": self.available,
            "cache_size": len(self._cache),
            "cache_ttl": self._cache.ttl if hasattr(self._cache, "ttl") else None,
        }
