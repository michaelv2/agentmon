"""Threat intelligence feed manager.

Downloads and caches external threat feeds (malware domains, C2 servers, phishing sites)
from reputable sources like abuse.ch.
"""

import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class ThreatFeedManager:
    """Manages downloading and caching of threat intelligence feeds."""

    def __init__(
        self,
        cache_dir: Path,
        update_interval_hours: int = 24,
        timeout_seconds: int = 30,
    ) -> None:
        """Initialize the threat feed manager.

        Args:
            cache_dir: Directory to cache downloaded feeds
            update_interval_hours: How often to refresh feeds
            timeout_seconds: HTTP request timeout
        """
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.update_interval = timedelta(hours=update_interval_hours)
        self.timeout = timeout_seconds
        self._domains: Optional[set[str]] = None

    def get_malicious_domains(self) -> set[str]:
        """Get the current set of malicious domains.

        Downloads feeds if cache is stale, otherwise loads from cache.

        Returns:
            Set of malicious domain names (lowercase)
        """
        if self._domains is not None:
            return self._domains

        # Update feeds if needed
        self.update_feeds()

        # Load all cached feeds
        domains = set()
        for cache_file in self.cache_dir.glob("*.txt"):
            try:
                domains.update(self._load_cache(cache_file))
            except Exception as e:
                logger.warning(f"Failed to load cached feed {cache_file.name}: {e}")

        self._domains = domains
        logger.info(f"Loaded {len(domains)} malicious domains from threat feeds")
        return domains

    def update_feeds(self) -> None:
        """Update all threat feeds if cache is stale."""
        feeds = [
            {
                "name": "urlhaus",
                "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
                "description": "URLhaus malware/C2 domains (abuse.ch)",
            },
            {
                "name": "feodo",
                "url": "https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
                "description": "Feodo Tracker botnet C2 (abuse.ch)",
            },
        ]

        for feed in feeds:
            cache_file = self.cache_dir / f"{feed['name']}.txt"

            if self._is_stale(cache_file):
                logger.info(f"Updating threat feed: {feed['description']}")
                try:
                    self._download_feed(feed["url"], cache_file)
                except Exception as e:
                    logger.warning(f"Failed to update {feed['name']}: {e}")
                    if not cache_file.exists():
                        # First-time download failed, create empty cache
                        logger.warning(f"Creating empty cache for {feed['name']}")
                        cache_file.write_text("")
            else:
                logger.debug(f"Threat feed {feed['name']} is up to date")

        # Clear cached domains to force reload
        self._domains = None

    def _is_stale(self, cache_file: Path) -> bool:
        """Check if a cached feed is stale.

        Args:
            cache_file: Path to the cached feed file

        Returns:
            True if cache doesn't exist or is older than update_interval
        """
        if not cache_file.exists():
            return True

        mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
        age = datetime.now() - mtime
        return age > self.update_interval

    def _download_feed(self, url: str, cache_file: Path) -> None:
        """Download a threat feed and save to cache.

        Args:
            url: Feed URL
            cache_file: Path to save the downloaded feed

        Raises:
            requests.RequestException: If download fails
        """
        resp = requests.get(url, timeout=self.timeout)
        resp.raise_for_status()

        # Write to temp file first, then rename (atomic)
        temp_file = cache_file.with_suffix(".tmp")
        temp_file.write_text(resp.text)
        temp_file.replace(cache_file)

        logger.info(f"Downloaded {cache_file.name} ({len(resp.text)} bytes)")

    def _load_cache(self, cache_file: Path) -> set[str]:
        """Load domains from a cached feed file.

        Parses plain text format (one domain per line, # comments ignored).

        Args:
            cache_file: Path to the cached feed file

        Returns:
            Set of domain names (lowercase, normalized)
        """
        domains = set()
        content = cache_file.read_text()

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Extract domain from various formats
            # URLhaus format: "http://malicious.com/path" or just "malicious.com"
            domain = self._extract_domain(line)
            if domain:
                domains.add(domain.lower())

        return domains

    def _extract_domain(self, line: str) -> Optional[str]:
        """Extract domain from a feed line.

        Handles various formats:
        - Plain domain: "malicious.com"
        - URL: "http://malicious.com/path"
        - IP address: skip (not a domain)

        Args:
            line: Feed line to parse

        Returns:
            Domain name or None if not a valid domain
        """
        # Try to extract from URL format
        url_match = re.match(r"^https?://([^/]+)", line)
        if url_match:
            domain = url_match.group(1)
        else:
            domain = line

        # Remove port if present
        domain = domain.split(":")[0]

        # Skip IP addresses (simple check)
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return None

        # Validate domain format (basic check)
        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
            return None

        return domain

    def check_domain(self, domain: str) -> Optional[str]:
        """Check if a domain is in the threat feeds.

        Args:
            domain: Domain name to check

        Returns:
            Feed name if domain is malicious, None otherwise
        """
        malicious = self.get_malicious_domains()

        # Exact match
        domain_lower = domain.lower()
        if domain_lower in malicious:
            return "threat_feed"

        # Check parent domains (e.g., "sub.malicious.com" matches "malicious.com")
        parts = domain_lower.split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if parent in malicious:
                return "threat_feed"

        return None

    def get_stats(self) -> dict:
        """Get statistics about loaded feeds.

        Returns:
            Dict with feed statistics
        """
        stats = {"total_domains": len(self.get_malicious_domains()), "feeds": []}

        for cache_file in sorted(self.cache_dir.glob("*.txt")):
            if cache_file.exists():
                mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                age = datetime.now() - mtime
                domain_count = len(self._load_cache(cache_file))

                stats["feeds"].append(
                    {
                        "name": cache_file.stem,
                        "domains": domain_count,
                        "updated": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                        "age_hours": int(age.total_seconds() / 3600),
                    }
                )

        return stats
