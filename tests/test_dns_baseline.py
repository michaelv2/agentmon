"""Tests for DNS baseline analyzer pattern matching and allowlist."""

from pathlib import Path

import pytest

from agentmon.analyzers.dns_baseline import AnalyzerConfig, DNSBaselineAnalyzer
from agentmon.storage import EventStore


class TestMatchesAtLabelBoundary:
    """Tests for label-boundary-aware pattern matching."""

    def test_pattern_at_domain_start(self) -> None:
        assert DNSBaselineAnalyzer._matches_at_label_boundary("c2-server.evil.com", "c2-")

    def test_pattern_after_dot(self) -> None:
        assert DNSBaselineAnalyzer._matches_at_label_boundary("sub.c2-server.evil.com", "c2-")

    def test_pattern_mid_label_no_match(self) -> None:
        """ec2- should NOT match the 'c2-' pattern."""
        assert not DNSBaselineAnalyzer._matches_at_label_boundary(
            "ec2-35-169-103-197.compute-1.amazonaws.com", "c2-"
        )

    def test_ec2_reverse_dns_no_match(self) -> None:
        """Real-world AWS EC2 reverse DNS must not trigger 'c2-' pattern."""
        aws_domains = [
            "ec2-3-15-42-7.us-east-2.compute.amazonaws.com",
            "ec2-35-169-103-197.compute-1.amazonaws.com",
            "ec2-54-210-99-44.compute-1.amazonaws.com",
        ]
        for domain in aws_domains:
            assert not DNSBaselineAnalyzer._matches_at_label_boundary(domain, "c2-"), (
                f"AWS domain {domain} should not match 'c2-'"
            )

    def test_actual_c2_domains_still_match(self) -> None:
        c2_domains = [
            "c2-server.net",
            "updates.c2-relay.io",
            "c2-callback.malware.ru",
        ]
        for domain in c2_domains:
            assert DNSBaselineAnalyzer._matches_at_label_boundary(domain, "c2-"), (
                f"C2 domain {domain} should match 'c2-'"
            )

    def test_case_insensitive(self) -> None:
        assert DNSBaselineAnalyzer._matches_at_label_boundary("C2-Server.net", "c2-")
        assert DNSBaselineAnalyzer._matches_at_label_boundary("c2-server.net", "C2-")

    def test_other_patterns_mid_label(self) -> None:
        """Other patterns that could appear mid-label should also be safe."""
        # 'rat-' inside 'integrate-...'
        assert not DNSBaselineAnalyzer._matches_at_label_boundary(
            "integrate-api.example.com", "rat-"
        )
        # but actual rat- at label start should match
        assert DNSBaselineAnalyzer._matches_at_label_boundary("rat-c2.evil.com", "rat-")

    def test_pattern_is_entire_label(self) -> None:
        assert DNSBaselineAnalyzer._matches_at_label_boundary("beacon.evil.com", "beacon")

    def test_alphanumeric_pattern_requires_end_boundary(self) -> None:
        """'beacon' should NOT match 'beacons2.gvt2.com' (Google telemetry)."""
        assert not DNSBaselineAnalyzer._matches_at_label_boundary(
            "beacons2.gvt2.com", "beacon"
        )
        assert not DNSBaselineAnalyzer._matches_at_label_boundary(
            "beaconfire.example.com", "beacon"
        )

    def test_alphanumeric_pattern_matches_exact_label(self) -> None:
        """'beacon' should still match when it IS the full label."""
        assert DNSBaselineAnalyzer._matches_at_label_boundary("beacon.evil.com", "beacon")
        assert DNSBaselineAnalyzer._matches_at_label_boundary("sub.beacon.evil.com", "beacon")
        assert DNSBaselineAnalyzer._matches_at_label_boundary("beacon", "beacon")

    def test_prefix_pattern_still_works(self) -> None:
        """Patterns ending with '-' act as label prefixes (no end boundary)."""
        assert DNSBaselineAnalyzer._matches_at_label_boundary("c2-server.evil.com", "c2-")
        assert DNSBaselineAnalyzer._matches_at_label_boundary("rat-callback.evil.com", "rat-")

    def test_no_match_at_all(self) -> None:
        assert not DNSBaselineAnalyzer._matches_at_label_boundary("google.com", "c2-")


class TestIsAllowlisted:
    """Tests for allowlist matching with wildcard support."""

    @pytest.fixture
    def analyzer(self) -> DNSBaselineAnalyzer:
        store = EventStore(Path(":memory:"))
        store.connect()
        config = AnalyzerConfig(
            allowlist={
                "localhost",
                "exact.example.com",
                "*.services.mozilla.com",
                "*.icloud.com",
            },
        )
        return DNSBaselineAnalyzer(store, config)

    def test_exact_match(self, analyzer: DNSBaselineAnalyzer) -> None:
        assert analyzer._is_allowlisted("localhost")
        assert analyzer._is_allowlisted("exact.example.com")

    def test_exact_no_match(self, analyzer: DNSBaselineAnalyzer) -> None:
        assert not analyzer._is_allowlisted("other.example.com")

    def test_wildcard_matches_subdomain(self, analyzer: DNSBaselineAnalyzer) -> None:
        assert analyzer._is_allowlisted("push.services.mozilla.com")
        assert analyzer._is_allowlisted("sync.services.mozilla.com")

    def test_wildcard_matches_deep_subdomain(self, analyzer: DNSBaselineAnalyzer) -> None:
        assert analyzer._is_allowlisted("a.b.services.mozilla.com")

    def test_wildcard_matches_parent_domain(self, analyzer: DNSBaselineAnalyzer) -> None:
        """*.icloud.com should also match icloud.com itself."""
        assert analyzer._is_allowlisted("icloud.com")

    def test_wildcard_no_partial_match(self, analyzer: DNSBaselineAnalyzer) -> None:
        """*.icloud.com should NOT match fakeicloud.com."""
        assert not analyzer._is_allowlisted("fakeicloud.com")
        assert not analyzer._is_allowlisted("noticloud.com")

    def test_wildcard_no_match_different_domain(self, analyzer: DNSBaselineAnalyzer) -> None:
        assert not analyzer._is_allowlisted("services.mozilla.org")
        assert not analyzer._is_allowlisted("evil.com")

    def test_empty_allowlist(self) -> None:
        store = EventStore(Path(":memory:"))
        store.connect()
        analyzer = DNSBaselineAnalyzer(store, AnalyzerConfig(allowlist=set()))
        assert not analyzer._is_allowlisted("anything.com")
