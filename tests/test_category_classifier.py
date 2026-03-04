"""Tests for category classifier domain matching."""

from agentmon.policies.category_classifier import classify_domain


class TestCategoryClassifierFalsePositives:
    """Test that substring matching doesn't produce false positives."""

    def test_riot_should_not_match_patriot(self) -> None:
        """'riot' pattern should not match 'patriot-act.gov'."""
        assert classify_domain("patriot-act.gov") == "unknown"

    def test_signal_should_not_match_signalprocessing(self) -> None:
        """'signal' pattern should not match 'signalprocessing.edu'."""
        assert classify_domain("signalprocessing.edu") == "unknown"

    def test_x_com_should_not_match_relax_com(self) -> None:
        """'x.com' pattern should not match 'relax.com'."""
        assert classify_domain("relax.com") == "unknown"

    def test_steam_should_not_match_upstream(self) -> None:
        """'steam' pattern should not match 'upstream.dev'."""
        assert classify_domain("upstream.dev") == "unknown"

    def test_ea_com_should_not_match_idea_com(self) -> None:
        """'ea.com' pattern should not match 'idea.com'."""
        assert classify_domain("idea.com") == "unknown"

    def test_riot_exact_domain_still_matches(self) -> None:
        """'riot.com' should still match the games category."""
        assert classify_domain("riot.com") == "games"

    def test_signal_exact_domain_still_matches(self) -> None:
        """'signal.org' should still match social_media."""
        assert classify_domain("signal.org") == "social_media"

    def test_x_com_exact_matches(self) -> None:
        """'x.com' should match social_media."""
        assert classify_domain("x.com") == "social_media"

    def test_subdomain_of_pattern_matches(self) -> None:
        """'api.roblox.com' should match games."""
        assert classify_domain("api.roblox.com") == "games"

    def test_www_prefix_matches(self) -> None:
        """'www.youtube.com' should match video."""
        assert classify_domain("www.youtube.com") == "video"

    def test_target_com_should_not_match_retarget(self) -> None:
        """'target.com' pattern should not match 'retarget.com'."""
        assert classify_domain("retarget.com") == "unknown"

    def test_bbc_com_should_not_match_subbbc(self) -> None:
        """'bbc.com' pattern should not match 'subbbc.com'."""
        assert classify_domain("subbbc.com") == "unknown"

    def test_edx_org_should_not_match_fedx_org(self) -> None:
        """'edx.org' should not match 'fedx.org'."""
        assert classify_domain("fedx.org") == "unknown"
