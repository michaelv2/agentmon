"""VirusTotal threat intelligence API integration.

Queries VirusTotal for real-time domain reputation and vendor detections.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import requests
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# VirusTotal API endpoint
VT_API_URL = "https://www.virustotal.com/api/v3/domains"

# Negative cache: 1 hour for failed lookups (avoids hammering a failing API)
# No positive cache here — the LLM classification cache (24h) serves that role.
NEGATIVE_CACHE_TTL = 3600

# Sentinel value for negative cache entries
_LOOKUP_FAILED = object()


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
        timeout: int = 10,
    ) -> None:
        """Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (None to disable)
            timeout: HTTP request timeout
        """
        self.api_key = api_key
        self.timeout = timeout
        self.available = api_key is not None

        # Negative cache only — avoids hammering a failing/rate-limited API.
        # Positive caching is handled by the LLM classification cache (24h),
        # which already stores the final result informed by VT data.
        self._neg_cache: TTLCache = TTLCache(maxsize=500, ttl=NEGATIVE_CACHE_TTL)

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

        # Check negative cache (recently failed lookups)
        if domain_lower in self._neg_cache:
            logger.debug(f"VirusTotal negative cache hit: {domain}")
            return None

        # Query API
        try:
            return self._query_api(domain_lower)
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for {domain}: {e}")
            self._neg_cache[domain_lower] = _LOOKUP_FAILED
            return None

    def _query_api(self, domain: str) -> Optional[VirusTotalReputation]:
        """Query VirusTotal API for domain reputation.

        Args:
            domain: Domain name to query

        Returns:
            VirusTotalReputation or None if domain not yet analyzed

        Raises:
            requests.RequestException: On API errors (rate limit, network, auth).
                Caller is responsible for error handling and negative caching.
        """
        headers = {"x-apikey": self.api_key}

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

    def get_stats(self) -> dict:
        """Get client statistics."""
        return {
            "available": self.available,
            "neg_cache_size": len(self._neg_cache),
        }
