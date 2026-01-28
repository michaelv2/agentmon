"""Tests for syslog receiver and parsers."""

import pytest
from datetime import datetime

from agentmon.collectors.syslog_receiver import (
    parse_syslog_message,
    SyslogMessage,
    SyslogConfig,
)
from agentmon.collectors.syslog_parsers import (
    PiholeParser,
    OpenWRTParser,
    route_message,
)


class TestSyslogMessageParsing:
    """Tests for syslog message parsing."""

    def test_rfc3164_basic(self) -> None:
        """Test RFC 3164 format parsing."""
        data = b"<30>Jan 26 14:32:15 myhost myapp[1234]: test message"
        msg = parse_syslog_message(data, "192.168.1.1")

        assert msg is not None
        assert msg.hostname == "myhost"
        assert msg.tag == "myapp"
        assert msg.message == "test message"
        assert msg.facility == 3  # daemon
        assert msg.severity == 6  # info
        assert msg.source_ip == "192.168.1.1"

    def test_rfc3164_no_pid(self) -> None:
        """Test RFC 3164 format without PID."""
        data = b"<30>Jan 26 14:32:15 myhost myapp: test message"
        msg = parse_syslog_message(data, "192.168.1.1")

        assert msg is not None
        assert msg.tag == "myapp"
        assert msg.message == "test message"

    def test_rfc5424_basic(self) -> None:
        """Test RFC 5424 format parsing."""
        data = b"<34>1 2024-01-26T14:32:15.000Z myhost myapp 1234 - - test message"
        msg = parse_syslog_message(data, "192.168.1.1")

        assert msg is not None
        assert msg.hostname == "myhost"
        assert msg.tag == "myapp"
        assert msg.message == "test message"

    def test_invalid_message(self) -> None:
        """Test handling of empty message."""
        msg = parse_syslog_message(b"", "192.168.1.1")
        assert msg is None

    def test_fallback_parsing(self) -> None:
        """Test fallback for non-standard format."""
        data = b"just a random message"
        msg = parse_syslog_message(data, "192.168.1.1")

        assert msg is not None
        assert msg.tag == "unknown"
        assert "random message" in msg.message

    def test_priority_decoding(self) -> None:
        """Test facility and severity decoding from priority."""
        # Priority 30 = facility 3 (daemon) * 8 + severity 6 (info)
        data = b"<30>Jan 26 14:32:15 host app: msg"
        msg = parse_syslog_message(data, "192.168.1.1")

        assert msg is not None
        assert msg.facility == 3
        assert msg.severity == 6
        assert msg.facility_name == "daemon"
        assert msg.severity_name == "info"


class TestPiholeParser:
    """Tests for Pi-hole/dnsmasq log parsing."""

    def test_can_parse_dnsmasq(self) -> None:
        """Test tag detection for dnsmasq messages."""
        msg = SyslogMessage(
            timestamp=datetime.now(),
            hostname="pihole",
            tag="dnsmasq",
            message="query[A] example.com from 192.168.1.100",
            source_ip="192.168.1.2",
        )
        assert PiholeParser.can_parse(msg) is True

    def test_can_parse_pihole_ftl(self) -> None:
        """Test tag detection for pihole-FTL."""
        msg = SyslogMessage(
            timestamp=datetime.now(),
            hostname="pihole",
            tag="pihole-FTL",
            message="some message",
            source_ip="192.168.1.2",
        )
        assert PiholeParser.can_parse(msg) is True

    def test_cannot_parse_other(self) -> None:
        """Test that unrelated tags are not matched."""
        msg = SyslogMessage(
            timestamp=datetime.now(),
            hostname="server",
            tag="sshd",
            message="login attempt",
            source_ip="192.168.1.2",
        )
        assert PiholeParser.can_parse(msg) is False

    def test_parse_query(self) -> None:
        """Test parsing DNS query."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="query[A] example.com from 192.168.1.100",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)

        assert event is not None
        assert event.domain == "example.com"
        assert event.client == "192.168.1.100"
        assert event.query_type == "A"
        assert event.blocked is False

    def test_parse_query_aaaa(self) -> None:
        """Test parsing AAAA query."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="query[AAAA] ipv6.example.com from 192.168.1.100",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)

        assert event is not None
        assert event.query_type == "AAAA"

    def test_parse_blocked_with_client(self) -> None:
        """Test parsing blocked entry with client IP."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="blacklisted malware.com from 192.168.1.100",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)

        assert event is not None
        assert event.domain == "malware.com"
        assert event.client == "192.168.1.100"
        assert event.blocked is True

    def test_parse_blocked_no_client(self) -> None:
        """Test parsing blocked entry without client IP returns correlation marker."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="gravity blocked ads.tracker.com is 0.0.0.0",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)

        assert event is not None
        assert event.domain == "ads.tracker.com"
        # Special marker indicates this needs correlation with recent query
        assert event.client == "__BLOCK_NOTIFICATION__"
        assert event.query_type == "BLOCK"
        assert event.blocked is True

    def test_parse_forward_ignored(self) -> None:
        """Test that forward messages are ignored."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="forwarded example.com to 8.8.8.8",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)
        assert event is None

    def test_parse_reply_ignored(self) -> None:
        """Test that reply messages are ignored."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="pihole",
            tag="dnsmasq",
            message="reply example.com is 93.184.216.34",
            source_ip="192.168.1.2",
        )
        event = PiholeParser.parse(msg)
        assert event is None


class TestOpenWRTParser:
    """Tests for OpenWRT firewall/conntrack parsing."""

    def test_can_parse_firewall(self) -> None:
        """Test tag detection for firewall messages."""
        msg = SyslogMessage(
            timestamp=datetime.now(),
            hostname="openwrt",
            tag="kernel",
            message="REJECT IN=br-lan OUT=eth0",
            source_ip="192.168.1.1",
        )
        assert OpenWRTParser.can_parse(msg) is True

    def test_can_parse_by_content(self) -> None:
        """Test detection by message content."""
        msg = SyslogMessage(
            timestamp=datetime.now(),
            hostname="openwrt",
            tag="unknown",
            message="DROP IN=br-lan OUT=eth0",
            source_ip="192.168.1.1",
        )
        assert OpenWRTParser.can_parse(msg) is True

    def test_parse_firewall_reject(self) -> None:
        """Test parsing firewall REJECT entry."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="openwrt",
            tag="kernel",
            message="REJECT IN=br-lan OUT=eth0.2 SRC=192.168.1.100 DST=1.2.3.4 PROTO=TCP SPT=54321 DPT=443",
            source_ip="192.168.1.1",
        )
        event = OpenWRTParser.parse_firewall(msg)

        assert event is not None
        assert event.client == "192.168.1.100"
        assert event.src_port == 54321
        assert event.dst_ip == "1.2.3.4"
        assert event.dst_port == 443
        assert event.protocol == "tcp"

    def test_parse_firewall_accept_ignored(self) -> None:
        """Test that ACCEPT entries are ignored."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="openwrt",
            tag="kernel",
            message="ACCEPT IN=br-lan OUT=eth0.2 SRC=192.168.1.100 DST=1.2.3.4 PROTO=TCP SPT=54321 DPT=443",
            source_ip="192.168.1.1",
        )
        event = OpenWRTParser.parse_firewall(msg)
        assert event is None

    def test_parse_conntrack_new(self) -> None:
        """Test parsing conntrack NEW entry."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="openwrt",
            tag="conntrack",
            message="[NEW] tcp 192.168.1.100:54321 -> 1.2.3.4:443 ASSURED",
            source_ip="192.168.1.1",
        )
        event = OpenWRTParser.parse_conntrack(msg)

        assert event is not None
        assert event.client == "192.168.1.100"
        assert event.src_port == 54321
        assert event.dst_ip == "1.2.3.4"
        assert event.dst_port == 443
        assert event.protocol == "tcp"

    def test_parse_conntrack_destroy_ignored(self) -> None:
        """Test that DESTROY entries are ignored."""
        msg = SyslogMessage(
            timestamp=datetime(2024, 1, 26, 14, 32, 15),
            hostname="openwrt",
            tag="conntrack",
            message="[DESTROY] tcp 192.168.1.100:54321 -> 1.2.3.4:443",
            source_ip="192.168.1.1",
        )
        event = OpenWRTParser.parse_conntrack(msg)
        assert event is None


class TestRouteMessage:
    """Tests for message routing."""

    def test_route_dns_query(self) -> None:
        """Test routing a DNS query message."""
        data = b"<30>Jan 26 14:32:15 pihole dnsmasq[1234]: query[A] example.com from 192.168.1.100"
        msg = parse_syslog_message(data, "192.168.1.2")
        assert msg is not None

        dns_event, conn_event = route_message(msg)
        assert dns_event is not None
        assert conn_event is None
        assert dns_event.domain == "example.com"

    def test_route_firewall_reject(self) -> None:
        """Test routing a firewall reject message."""
        data = b"<6>Jan 26 14:32:15 openwrt kernel: REJECT IN=br-lan OUT=eth0 SRC=192.168.1.100 DST=1.2.3.4 PROTO=TCP SPT=1234 DPT=443"
        msg = parse_syslog_message(data, "192.168.1.1")
        assert msg is not None

        dns_event, conn_event = route_message(msg)
        assert dns_event is None
        assert conn_event is not None
        assert conn_event.dst_port == 443

    def test_route_unrelated_message(self) -> None:
        """Test routing an unrelated message."""
        data = b"<30>Jan 26 14:32:15 server sshd[1234]: session opened for user root"
        msg = parse_syslog_message(data, "192.168.1.10")
        assert msg is not None

        dns_event, conn_event = route_message(msg)
        assert dns_event is None
        assert conn_event is None


class TestSyslogConfig:
    """Tests for syslog configuration."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = SyslogConfig()
        assert config.port == 1514
        assert config.protocol == "udp"
        assert config.bind_address == "0.0.0.0"
        assert config.allowed_ips == []

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = SyslogConfig(
            port=5514,
            protocol="tcp",
            bind_address="192.168.1.1",
            allowed_ips=["192.168.1.2", "192.168.1.3"],
        )
        assert config.port == 5514
        assert config.protocol == "tcp"
        assert config.bind_address == "192.168.1.1"
        assert config.allowed_ips == ["192.168.1.2", "192.168.1.3"]
