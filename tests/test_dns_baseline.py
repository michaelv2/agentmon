"""Tests for DNS baseline analyzer known-bad pattern matching."""

import pytest

from agentmon.analyzers.dns_baseline import DNSBaselineAnalyzer


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

    def test_no_match_at_all(self) -> None:
        assert not DNSBaselineAnalyzer._matches_at_label_boundary("google.com", "c2-")
