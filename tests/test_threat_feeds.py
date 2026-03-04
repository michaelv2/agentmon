"""Tests for threat feed content validation."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from agentmon.threat_feeds import ThreatFeedManager


class TestFeedContentValidation:
    """Test that threat feeds validate content before overwriting cache."""

    def test_empty_response_does_not_overwrite_existing_cache(
        self, tmp_path: Path
    ) -> None:
        """A 200 response with empty body should not overwrite a populated cache."""
        cache_dir = tmp_path / "feeds"
        cache_dir.mkdir()

        # Pre-populate cache with valid data
        cache_file = cache_dir / "urlhaus.txt"
        cache_file.write_text("malware1.com\nmalware2.com\nmalware3.com\n")

        manager = ThreatFeedManager(cache_dir=cache_dir)

        # Mock HTTP response with empty body
        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch("agentmon.threat_feeds.requests.get", return_value=mock_resp):
            manager._download_feed("http://example.com/feed", cache_file)

        # Cache should still contain the original data
        content = cache_file.read_text()
        assert "malware1.com" in content

    def test_garbage_response_does_not_overwrite_existing_cache(
        self, tmp_path: Path
    ) -> None:
        """A 200 response with garbage (no valid domains) should not overwrite."""
        cache_dir = tmp_path / "feeds"
        cache_dir.mkdir()

        cache_file = cache_dir / "urlhaus.txt"
        cache_file.write_text("malware1.com\nmalware2.com\n")

        manager = ThreatFeedManager(cache_dir=cache_dir)

        mock_resp = MagicMock()
        mock_resp.text = "<!DOCTYPE html><html><body>Error</body></html>"
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch("agentmon.threat_feeds.requests.get", return_value=mock_resp):
            manager._download_feed("http://example.com/feed", cache_file)

        content = cache_file.read_text()
        assert "malware1.com" in content

    def test_valid_response_overwrites_cache(self, tmp_path: Path) -> None:
        """A response with valid domains should overwrite the cache."""
        cache_dir = tmp_path / "feeds"
        cache_dir.mkdir()

        cache_file = cache_dir / "urlhaus.txt"
        cache_file.write_text("old-malware.com\n")

        manager = ThreatFeedManager(cache_dir=cache_dir)

        mock_resp = MagicMock()
        mock_resp.text = "new-malware1.com\nnew-malware2.com\n"
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch("agentmon.threat_feeds.requests.get", return_value=mock_resp):
            manager._download_feed("http://example.com/feed", cache_file)

        content = cache_file.read_text()
        assert "new-malware1.com" in content
        assert "old-malware" not in content

    def test_empty_response_ok_when_no_existing_cache(
        self, tmp_path: Path
    ) -> None:
        """Empty response is fine when there's no existing cache to protect."""
        cache_dir = tmp_path / "feeds"
        cache_dir.mkdir()

        cache_file = cache_dir / "urlhaus.txt"
        # No pre-existing cache

        manager = ThreatFeedManager(cache_dir=cache_dir)

        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch("agentmon.threat_feeds.requests.get", return_value=mock_resp):
            manager._download_feed("http://example.com/feed", cache_file)

        # File should exist (empty is fine for first download)
        assert cache_file.exists()
