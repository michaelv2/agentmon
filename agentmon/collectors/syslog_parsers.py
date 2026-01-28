"""Syslog message parsers for different log sources.

Each parser takes a SyslogMessage and extracts structured events
(DNSEvent, ConnectionEvent, etc.) from the message content.
"""

import re

from agentmon.collectors.syslog_receiver import SyslogMessage
from agentmon.models import ConnectionEvent, DNSEvent

# Pi-hole/dnsmasq query patterns (same as pihole_log.py but for message content only)
DNSMASQ_QUERY_PATTERN = re.compile(
    r"^query\[(\w+)\]\s+"  # Query type: "query[A]"
    r"(\S+)\s+"             # Domain
    r"from\s+(\S+)"         # Client IP
)

# Blocked entries can be in two formats:
# "gravity blocked malware.com is 0.0.0.0" (response is 0.0.0.0, no client info)
# "blacklisted malware.com from 192.168.1.100" (has client info)
DNSMASQ_BLOCKED_WITH_CLIENT_PATTERN = re.compile(
    r"^(?:gravity blocked|blacklisted|regex blocked)\s+"
    r"(\S+)\s+"              # Domain
    r"from\s+(\S+)"          # Client IP
)

DNSMASQ_BLOCKED_NO_CLIENT_PATTERN = re.compile(
    r"^(?:gravity blocked|blacklisted|regex blocked)\s+"
    r"(\S+)\s+"              # Domain
    r"is\s+"                 # "is" indicates this is the response line, not client
)

DNSMASQ_FORWARD_PATTERN = re.compile(
    r"^forwarded\s+(\S+)\s+to\s+(\S+)"  # Domain, upstream
)

DNSMASQ_REPLY_PATTERN = re.compile(
    r"^reply\s+(\S+)\s+is\s+(.+)"  # Domain, answer
)

# OpenWRT firewall log patterns
# Example: "REJECT IN=br-lan OUT=eth0.2 SRC=192.168.1.100 DST=1.2.3.4 PROTO=TCP DPT=443"
OPENWRT_FIREWALL_PATTERN = re.compile(
    r"^(ACCEPT|REJECT|DROP)\s+"
    r"IN=(\S*)\s+"
    r"OUT=(\S*)\s+"
    r"(?:MAC=\S+\s+)?"  # Optional MAC
    r"SRC=(\S+)\s+"
    r"DST=(\S+)\s+"
    r".*?"
    r"PROTO=(\w+)"
    r"(?:.*?SPT=(\d+))?"
    r"(?:.*?DPT=(\d+))?"
)

# OpenWRT conntrack patterns
# Example: "[DESTROY] tcp 192.168.1.100:54321 -> 1.2.3.4:443 ASSURED"
OPENWRT_CONNTRACK_PATTERN = re.compile(
    r"^\[(NEW|UPDATE|DESTROY)\]\s+"
    r"(\w+)\s+"  # Protocol
    r"(\S+):(\d+)\s+"  # Source IP:port
    r"->\s+"
    r"(\S+):(\d+)"  # Dest IP:port
)


class PiholeParser:
    """Parser for Pi-hole/dnsmasq syslog messages."""

    # Tags that indicate dnsmasq messages (lowercase for comparison)
    DNSMASQ_TAGS = {"dnsmasq", "dnsmasq-dhcp", "pihole-ftl", "pihole"}

    @classmethod
    def can_parse(cls, msg: SyslogMessage) -> bool:
        """Check if this parser can handle the message."""
        tag_lower = msg.tag.lower()
        return (
            tag_lower in cls.DNSMASQ_TAGS
            or tag_lower.startswith("dnsmasq")
            or tag_lower.startswith("pihole")
        )

    # Pattern to extract dnsmasq content from embedded log lines
    # Matches: "Jan 28 01:14:11 dnsmasq[6587]: query[A] ..." or just "query[A] ..."
    EMBEDDED_DNSMASQ_PATTERN = re.compile(
        r"(?:.*?dnsmasq\[\d+\]:\s*)?(query\[|forwarded|reply|gravity blocked|blacklisted|regex blocked|cached)"
    )

    @classmethod
    def parse(cls, msg: SyslogMessage) -> DNSEvent | None:
        """Parse a dnsmasq syslog message into a DNSEvent.

        Args:
            msg: The syslog message to parse

        Returns:
            DNSEvent if the message is a DNS query, None otherwise
        """
        content = msg.message.strip()

        # Handle embedded dnsmasq format from tail | logger
        # e.g., "Jan 28 01:14:11 dnsmasq[6587]: query[A] example.com from 192.168.1.100"
        dnsmasq_marker = "dnsmasq["
        if dnsmasq_marker in content:
            # Find the colon after dnsmasq[pid] and extract the rest
            marker_pos = content.find(dnsmasq_marker)
            colon_pos = content.find(":", marker_pos)
            if colon_pos != -1:
                content = content[colon_pos + 1:].strip()

        # Query pattern
        match = DNSMASQ_QUERY_PATTERN.match(content)
        if match:
            query_type, domain, client = match.groups()
            return DNSEvent(
                timestamp=msg.timestamp,
                client=client,
                domain=domain,
                query_type=query_type,
                blocked=False,
            )

        # Blocked pattern with client IP
        match = DNSMASQ_BLOCKED_WITH_CLIENT_PATTERN.match(content)
        if match:
            domain, client = match.groups()
            return DNSEvent(
                timestamp=msg.timestamp,
                client=client,
                domain=domain,
                query_type="A",  # Blocked entries don't always show query type
                blocked=True,
            )

        # Blocked pattern without client IP (uses syslog source as fallback)
        match = DNSMASQ_BLOCKED_NO_CLIENT_PATTERN.match(content)
        if match:
            domain = match.group(1)
            # Use the hostname from the syslog message as the client identifier
            # This is a best-effort fallback when client IP isn't in the log line
            client = msg.source_ip or msg.hostname
            return DNSEvent(
                timestamp=msg.timestamp,
                client=client,
                domain=domain,
                query_type="A",
                blocked=True,
            )

        # Forward and reply messages are informational, skip for now
        # (could be used to track upstream latency in the future)
        return None


class OpenWRTParser:
    """Parser for OpenWRT syslog messages (firewall, conntrack)."""

    # Tags that indicate OpenWRT firewall/network messages
    FIREWALL_TAGS = {"kernel", "fw3", "firewall"}
    CONNTRACK_TAGS = {"conntrack", "conntrackd"}

    @classmethod
    def can_parse(cls, msg: SyslogMessage) -> bool:
        """Check if this parser can handle the message."""
        tag_lower = msg.tag.lower()
        return (
            tag_lower in cls.FIREWALL_TAGS
            or tag_lower in cls.CONNTRACK_TAGS
            or "REJECT" in msg.message
            or "ACCEPT" in msg.message
            or "DROP" in msg.message
        )

    @classmethod
    def parse_firewall(cls, msg: SyslogMessage) -> ConnectionEvent | None:
        """Parse an OpenWRT firewall log message.

        Args:
            msg: The syslog message to parse

        Returns:
            ConnectionEvent if the message is a firewall log, None otherwise
        """
        match = OPENWRT_FIREWALL_PATTERN.search(msg.message)
        if not match:
            return None

        action, in_iface, out_iface, src_ip, dst_ip, proto, src_port, dst_port = match.groups()

        # Only track REJECT/DROP for now (blocked connections)
        # Could expand to track all connections if needed
        if action == "ACCEPT":
            return None

        return ConnectionEvent(
            timestamp=msg.timestamp,
            client=src_ip,
            src_port=int(src_port) if src_port else 0,
            dst_ip=dst_ip,
            dst_port=int(dst_port) if dst_port else 0,
            protocol=proto.lower(),
        )

    @classmethod
    def parse_conntrack(cls, msg: SyslogMessage) -> ConnectionEvent | None:
        """Parse an OpenWRT conntrack message.

        Args:
            msg: The syslog message to parse

        Returns:
            ConnectionEvent for connection state changes
        """
        match = OPENWRT_CONNTRACK_PATTERN.search(msg.message)
        if not match:
            return None

        event_type, proto, src_ip, src_port, dst_ip, dst_port = match.groups()

        # Only track NEW connections to avoid duplicates
        if event_type != "NEW":
            return None

        return ConnectionEvent(
            timestamp=msg.timestamp,
            client=src_ip,
            src_port=int(src_port),
            dst_ip=dst_ip,
            dst_port=int(dst_port),
            protocol=proto.lower(),
        )

    @classmethod
    def parse(cls, msg: SyslogMessage) -> ConnectionEvent | None:
        """Parse an OpenWRT message into a ConnectionEvent.

        Tries firewall log first, then conntrack.
        """
        event = cls.parse_firewall(msg)
        if event:
            return event

        return cls.parse_conntrack(msg)


def route_message(msg: SyslogMessage) -> tuple[DNSEvent | None, ConnectionEvent | None]:
    """Route a syslog message to the appropriate parser.

    Args:
        msg: The syslog message to route

    Returns:
        Tuple of (dns_event, connection_event), either or both may be None
    """
    dns_event = None
    conn_event = None

    # Try Pi-hole/dnsmasq parser
    if PiholeParser.can_parse(msg):
        dns_event = PiholeParser.parse(msg)

    # Try OpenWRT parser
    if OpenWRTParser.can_parse(msg):
        conn_event = OpenWRTParser.parse(msg)

    return dns_event, conn_event
