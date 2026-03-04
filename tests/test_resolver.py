"""Tests for client identity resolution."""

import socket
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import dns.resolver

from agentmon.resolver import ClientResolver, ResolverConfig


class TestExplicitMappings:
    def test_mapping_takes_priority_over_dns(self) -> None:
        config = ResolverConfig(
            enabled=True,
            mappings={"192.168.1.50": "alice-laptop"},
        )
        resolver = ClientResolver(config)
        assert resolver.resolve("192.168.1.50") == "alice-laptop"

    def test_unmapped_ip_falls_through(self) -> None:
        """IP not in mappings should attempt DNS lookup."""
        config = ResolverConfig(
            enabled=True,
            mappings={"192.168.1.50": "alice-laptop"},
        )
        resolver = ClientResolver(config)
        with patch.object(resolver, "_reverse_lookup", return_value=None):
            assert resolver.resolve("192.168.1.99") == "192.168.1.99"


class TestDisabled:
    def test_disabled_returns_raw_ip(self) -> None:
        config = ResolverConfig(enabled=False)
        resolver = ClientResolver(config)
        assert resolver.resolve("192.168.1.50") == "192.168.1.50"


class TestDnspythonLookup:
    """PTR lookup via dnspython when dns_server is configured."""

    def test_successful_ptr_lookup(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        mock_answer = MagicMock()
        mock_answer.__getitem__ = lambda self, idx: MagicMock(
            __str__=lambda self: "alice-laptop.lan."
        )

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_resolver = mock_cls.return_value
            mock_resolver.resolve.return_value = mock_answer
            result = resolver.resolve("192.168.1.50")

        assert result == "alice-laptop"
        mock_resolver.resolve.assert_called_once()

    def test_nameserver_is_set(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        mock_answer = MagicMock()
        mock_answer.__getitem__ = lambda self, idx: MagicMock(
            __str__=lambda self: "host.lan."
        )

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_resolver = mock_cls.return_value
            mock_resolver.resolve.return_value = mock_answer
            resolver.resolve("192.168.1.50")

        mock_cls.assert_called_once_with(configure=False)
        assert mock_resolver.nameservers == ["10.0.0.1"]

    def test_strip_suffix_disabled(self) -> None:
        config = ResolverConfig(
            enabled=True, dns_server="10.0.0.1", strip_suffix=False
        )
        resolver = ClientResolver(config)

        mock_answer = MagicMock()
        mock_answer.__getitem__ = lambda self, idx: MagicMock(
            __str__=lambda self: "alice-laptop.lan."
        )

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_cls.return_value.resolve.return_value = mock_answer
            result = resolver.resolve("192.168.1.50")

        assert result == "alice-laptop.lan"

    def test_nxdomain_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_cls.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"

    def test_no_answer_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_cls.return_value.resolve.side_effect = dns.resolver.NoAnswer()
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"

    def test_timeout_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_cls.return_value.resolve.side_effect = dns.resolver.LifetimeTimeout()
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"

    def test_no_nameservers_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server="10.0.0.1")
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.dns.resolver.Resolver") as mock_cls:
            mock_cls.return_value.resolve.side_effect = dns.resolver.NoNameservers()
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"


class TestSocketFallback:
    """PTR lookup via socket.gethostbyaddr when dns_server is not set."""

    def test_successful_lookup(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("bob-desktop.home.local", [], ["192.168.1.60"])
            result = resolver.resolve("192.168.1.60")

        assert result == "bob-desktop"

    def test_strip_suffix_disabled(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None, strip_suffix=False)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("bob-desktop.home.local", [], ["192.168.1.60"])
            result = resolver.resolve("192.168.1.60")

        assert result == "bob-desktop.home.local"

    def test_herror_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.herror("No PTR record")
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"

    def test_gaierror_returns_ip(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.gaierror("DNS resolution failed")
            result = resolver.resolve("192.168.1.99")

        assert result == "192.168.1.99"


class TestCache:
    def test_positive_cache_hit(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("cached-host.lan", [], ["192.168.1.70"])
            # First call: populates cache
            result1 = resolver.resolve("192.168.1.70")

        # Second call: should use cache (mock is no longer active)
        result2 = resolver.resolve("192.168.1.70")

        assert result1 == "cached-host"
        assert result2 == "cached-host"

    def test_negative_cache_prevents_retry(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.herror("No PTR record")
            resolver.resolve("192.168.1.99")
            resolver.resolve("192.168.1.99")

        # gethostbyaddr should only be called once; second call hits negative cache
        assert mock_gethostbyaddr.call_count == 1

    def test_negative_cache_expires(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.herror("No PTR record")
            resolver.resolve("192.168.1.99")

        # Expire the negative cache
        resolver._failed_cache["192.168.1.99"] = datetime.now(UTC) - timedelta(seconds=1)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.herror("No PTR record")
            resolver.resolve("192.168.1.99")
            assert mock_gethostbyaddr.call_count == 1

    def test_clear_cache(self) -> None:
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("host.lan", [], ["192.168.1.70"])
            resolver.resolve("192.168.1.70")

        resolver.clear_cache()

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("host.lan", [], ["192.168.1.70"])
            resolver.resolve("192.168.1.70")
            assert mock_gethostbyaddr.call_count == 1  # Had to re-query after cache clear


class TestCacheStats:
    def test_stats_reflect_state(self) -> None:
        config = ResolverConfig(
            enabled=True,
            dns_server=None,
            mappings={"10.0.0.1": "router"},
        )
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("host.lan", [], ["192.168.1.70"])
            resolver.resolve("192.168.1.70")

            mock_gethostbyaddr.side_effect = socket.herror("No PTR")
            resolver.resolve("192.168.1.99")

        stats = resolver.get_cache_stats()
        assert stats["positive_entries"] == 1
        assert stats["negative_entries"] == 1
        assert stats["explicit_mappings"] == 1


class TestUTCDatetimes:
    """Test that resolver uses UTC-aware datetimes internally."""

    def test_positive_cache_uses_utc(self) -> None:
        """Positive cache expiry timestamps should be UTC-aware."""
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock:
            mock.return_value = ("host.lan", [], ["192.168.1.70"])
            resolver.resolve("192.168.1.70")

        _, expires = resolver._cache["192.168.1.70"]
        assert expires.tzinfo is not None

    def test_negative_cache_uses_utc(self) -> None:
        """Negative cache expiry timestamps should be UTC-aware."""
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock:
            mock.side_effect = socket.herror("No PTR record")
            resolver.resolve("192.168.1.99")

        failed_until = resolver._failed_cache["192.168.1.99"]
        assert failed_until.tzinfo is not None

    def test_cache_stats_uses_utc(self) -> None:
        """get_cache_stats should compare with UTC-aware datetimes."""
        config = ResolverConfig(enabled=True, dns_server=None)
        resolver = ClientResolver(config)

        with patch("agentmon.resolver.socket.gethostbyaddr") as mock:
            mock.return_value = ("host.lan", [], ["192.168.1.70"])
            resolver.resolve("192.168.1.70")

        # Should not raise on comparison with UTC-aware datetime
        stats = resolver.get_cache_stats()
        assert stats["positive_entries"] == 1
