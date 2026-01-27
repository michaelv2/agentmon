"""Tests for entropy-based domain analysis."""

import pytest

from agentmon.analyzers.entropy import (
    calculate_entropy,
    calculate_domain_entropy,
    is_high_entropy_domain,
    has_excessive_consonants,
    looks_like_dga,
)


class TestCalculateEntropy:
    def test_empty_string(self) -> None:
        assert calculate_entropy("") == 0.0

    def test_single_character(self) -> None:
        assert calculate_entropy("aaaa") == 0.0

    def test_two_characters_equal(self) -> None:
        # "ab" has 2 chars, each with probability 0.5
        # entropy = -2 * (0.5 * log2(0.5)) = 1.0
        result = calculate_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_random_looking_string(self) -> None:
        # High entropy string
        result = calculate_entropy("a8kd92jfm3nv8d")
        assert result > 3.0


class TestDomainEntropy:
    def test_normal_domain(self) -> None:
        entropy = calculate_domain_entropy("google.com")
        assert entropy < 3.0  # Normal domain, low entropy

    def test_random_subdomain(self) -> None:
        entropy = calculate_domain_entropy("x8a9d7f3k2m1.evil.com")
        assert entropy > 3.0  # Random-looking, high entropy


class TestHighEntropyDomain:
    def test_normal_domain_not_flagged(self) -> None:
        is_high, _ = is_high_entropy_domain("google.com")
        assert not is_high

    def test_random_domain_flagged(self) -> None:
        is_high, entropy = is_high_entropy_domain("a8k3m9d7f2x1z5.com")
        assert is_high
        assert entropy > 3.5

    def test_short_domain_not_flagged(self) -> None:
        # Short domains shouldn't trigger even if high entropy
        is_high, _ = is_high_entropy_domain("x9.com", min_length=10)
        assert not is_high


class TestExcessiveConsonants:
    def test_normal_word(self) -> None:
        assert not has_excessive_consonants("facebook.com")

    def test_consonant_heavy(self) -> None:
        assert has_excessive_consonants("xkcd-mngmnt-prblm.com")


class TestDGADetection:
    def test_normal_domain(self) -> None:
        is_dga, reasons = looks_like_dga("amazon.com")
        assert not is_dga
        assert len(reasons) < 2

    def test_known_good_services(self) -> None:
        """Test that common legitimate services aren't flagged."""
        normal_domains = [
            "google.com",
            "api.github.com",
            "cdn.cloudflare.com",
            "updates.microsoft.com",
        ]
        for domain in normal_domains:
            is_dga, _ = looks_like_dga(domain)
            assert not is_dga, f"{domain} was incorrectly flagged as DGA"

    def test_obvious_dga(self) -> None:
        """Test obviously random domains."""
        dga_domains = [
            "a8k3m9d7f2x1z5q4w8.com",
            "xyzklmnpqrstvwxz.net",
        ]
        for domain in dga_domains:
            is_dga, reasons = looks_like_dga(domain)
            assert is_dga, f"{domain} should be flagged as DGA"
            assert len(reasons) >= 2
