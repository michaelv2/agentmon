"""Syslog receiver for push-based log collection.

Receives syslog messages from edge devices (Pi-hole, OpenWRT) over UDP/TCP.
This replaces SSH-based pull collection, improving security by ensuring
the hub holds no credentials to network infrastructure.

Supports:
- RFC 3164 (BSD syslog) format
- RFC 5424 (modern syslog) format
- UDP and TCP protocols
- Optional IP allowlist for security
"""

import asyncio
import logging
import re
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


# RFC 3164 priority and timestamp pattern
# <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
RFC3164_PATTERN = re.compile(
    r"^<(\d{1,3})>"  # Priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp: "Jan 26 14:32:15"
    r"(\S+)\s+"  # Hostname
    r"(\S+?)(?:\[\d+\])?:\s*"  # Tag (program name), optional PID
    r"(.*)$"  # Message
)

# RFC 5424 pattern
# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"^<(\d{1,3})>(\d)\s+"  # Priority and version
    r"(\S+)\s+"  # Timestamp (ISO 8601)
    r"(\S+)\s+"  # Hostname
    r"(\S+)\s+"  # App-name
    r"(\S+)\s+"  # Procid
    r"(\S+)\s+"  # Msgid
    r"(?:\[.*?\]|-)\s*"  # Structured-data (skip for now)
    r"(.*)$"  # Message
)


@dataclass
class SyslogMessage:
    """Parsed syslog message."""

    timestamp: datetime
    hostname: str
    tag: str  # Program/application name (e.g., "dnsmasq", "dropbear")
    message: str
    facility: int = 0
    severity: int = 0
    source_ip: str | None = None

    @property
    def facility_name(self) -> str:
        """Human-readable facility name."""
        facilities = [
            "kern", "user", "mail", "daemon", "auth", "syslog",
            "lpr", "news", "uucp", "cron", "authpriv", "ftp",
            "ntp", "audit", "alert", "clock",
            "local0", "local1", "local2", "local3",
            "local4", "local5", "local6", "local7",
        ]
        if self.facility < len(facilities):
            return facilities[self.facility]
        return f"facility{self.facility}"

    @property
    def severity_name(self) -> str:
        """Human-readable severity name."""
        severities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        if self.severity < len(severities):
            return severities[self.severity]
        return f"severity{self.severity}"


@dataclass
class SyslogConfig:
    """Configuration for syslog receiver."""

    port: int = 1514
    protocol: str = "udp"  # "udp", "tcp", or "both"
    bind_address: str = "0.0.0.0"
    allowed_ips: list[str] = field(default_factory=list)  # Empty = allow all
    year: int = field(default_factory=lambda: datetime.now().year)
    buffer_size: int = 65535  # Max UDP packet size
    rate_limit_per_second: int = 0  # 0 = disabled; per-IP token bucket


# Maximum syslog message size to prevent ReDoS attacks
# RFC 5424 recommends 2048 bytes minimum, we allow up to 8KB to be generous
MAX_SYSLOG_MESSAGE_LENGTH = 8192

# Maximum TCP buffer size to prevent OOM from senders that never send newlines.
# 64KB is generous for any valid syslog message.
MAX_TCP_BUFFER_SIZE = 65536


def parse_syslog_message(
    data: bytes,
    source_ip: str,
    year: int | None = None,
) -> SyslogMessage | None:
    """Parse a raw syslog message.

    Args:
        data: Raw syslog message bytes
        source_ip: IP address of the sender
        year: Year to use for timestamps (syslog often omits year)

    Returns:
        Parsed SyslogMessage or None if parsing fails

    Security:
        Enforces maximum message length to prevent ReDoS attacks via
        crafted messages that cause catastrophic regex backtracking.
    """
    if year is None:
        year = datetime.now().year

    # Security: Enforce maximum message size to prevent ReDoS
    if len(data) > MAX_SYSLOG_MESSAGE_LENGTH:
        logger.warning(
            f"Oversized syslog message from {source_ip}: {len(data)} bytes "
            f"(max {MAX_SYSLOG_MESSAGE_LENGTH}) - dropped"
        )
        return None

    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    if not text:
        return None

    # Try RFC 5424 first (has version number after priority)
    match = RFC5424_PATTERN.match(text)
    if match:
        pri, _version, timestamp_str, hostname, app_name, _procid, _msgid, message = match.groups()
        priority = int(pri)
        facility = priority >> 3
        severity = priority & 0x07

        # Parse ISO 8601 timestamp
        try:
            # Handle common formats
            timestamp_str = timestamp_str.replace("Z", "+00:00")
            if "T" in timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str)
            else:
                timestamp = datetime.now()
        except ValueError:
            timestamp = datetime.now()

        return SyslogMessage(
            timestamp=timestamp,
            hostname=hostname,
            tag=app_name,
            message=message,
            facility=facility,
            severity=severity,
            source_ip=source_ip,
        )

    # Try RFC 3164
    match = RFC3164_PATTERN.match(text)
    if match:
        pri, timestamp_str, hostname, tag, message = match.groups()
        priority = int(pri)
        facility = priority >> 3
        severity = priority & 0x07

        # Parse BSD timestamp (no year)
        try:
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            timestamp = dt.replace(year=year)
        except ValueError:
            timestamp = datetime.now()

        return SyslogMessage(
            timestamp=timestamp,
            hostname=hostname,
            tag=tag,
            message=message,
            facility=facility,
            severity=severity,
            source_ip=source_ip,
        )

    # Fallback: treat entire message as content
    return SyslogMessage(
        timestamp=datetime.now(),
        hostname=source_ip,
        tag="unknown",
        message=text,
        source_ip=source_ip,
    )


class _PerIPRateLimiter:
    """Simple per-IP token bucket rate limiter.

    Each IP gets `rate` tokens per second; a message consumes one token.
    When tokens are exhausted, messages are silently dropped.
    """

    def __init__(self, rate: int) -> None:
        self.rate = rate  # tokens per second; 0 means disabled
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_ts)

    def allow(self, ip: str) -> bool:
        """Return True if the message from *ip* should be processed."""
        if self.rate <= 0:
            return True

        now = time.monotonic()
        tokens, last_ts = self._buckets.get(ip, (float(self.rate), now))

        # Refill tokens based on elapsed time
        elapsed = now - last_ts
        tokens = min(float(self.rate), tokens + elapsed * self.rate)

        if tokens >= 1.0:
            self._buckets[ip] = (tokens - 1.0, now)
            return True

        self._buckets[ip] = (tokens, now)
        return False


# Type alias for message handler callback
MessageHandler = Callable[[SyslogMessage], None]


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(
        self,
        handler: MessageHandler,
        config: SyslogConfig,
    ) -> None:
        self.handler = handler
        self.config = config
        self.transport: asyncio.DatagramTransport | None = None
        self._rate_limiter = _PerIPRateLimiter(config.rate_limit_per_second)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]

        # Check IP allowlist
        if self.config.allowed_ips and source_ip not in self.config.allowed_ips:
            logger.debug(f"Rejected syslog from {source_ip} (not in allowlist)")
            return

        # Per-IP rate limiting
        if not self._rate_limiter.allow(source_ip):
            logger.debug(f"Rate limited syslog from {source_ip}")
            return

        msg = parse_syslog_message(data, source_ip, self.config.year)
        if msg:
            try:
                self.handler(msg)
            except Exception as e:
                logger.error(f"Error handling syslog message: {e}")


class TCPSyslogProtocol(asyncio.Protocol):
    """TCP protocol handler for syslog messages."""

    def __init__(
        self,
        handler: MessageHandler,
        config: SyslogConfig,
    ) -> None:
        self.handler = handler
        self.config = config
        self.transport: asyncio.Transport | None = None
        self.buffer = b""
        self.peer: tuple[str, int] | None = None
        self._rate_limiter = _PerIPRateLimiter(config.rate_limit_per_second)

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.peer = transport.get_extra_info("peername")

        if self.peer:
            source_ip = self.peer[0]
            if self.config.allowed_ips and source_ip not in self.config.allowed_ips:
                logger.debug(f"Rejected TCP connection from {source_ip} (not in allowlist)")
                transport.close()
                return

        logger.debug(f"TCP connection from {self.peer}")

    def data_received(self, data: bytes) -> None:
        self.buffer += data

        # Process complete messages (newline-delimited for TCP syslog)
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if line:
                source_ip = self.peer[0] if self.peer else "unknown"
                # Per-IP rate limiting
                if not self._rate_limiter.allow(source_ip):
                    logger.debug(f"Rate limited TCP syslog from {source_ip}")
                    continue
                msg = parse_syslog_message(line, source_ip, self.config.year)
                if msg:
                    try:
                        self.handler(msg)
                    except Exception as e:
                        logger.error(f"Error handling syslog message: {e}")

        # Guard against unbounded buffer growth (OOM protection)
        # Check AFTER processing complete messages — a large burst of
        # newline-delimited messages should be drained, not discarded.
        # Only a single incomplete message (no newline) should remain.
        if len(self.buffer) > MAX_TCP_BUFFER_SIZE:
            logger.warning(
                "TCP buffer overflow from %s: %d bytes (max %d) - closing connection",
                self.peer, len(self.buffer), MAX_TCP_BUFFER_SIZE,
            )
            self.buffer = b""
            if self.transport:
                self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug(f"TCP connection closed from {self.peer}")


class SyslogReceiver:
    """Async syslog receiver supporting UDP and TCP."""

    def __init__(
        self,
        config: SyslogConfig,
        handler: MessageHandler,
    ) -> None:
        """Initialize the syslog receiver.

        Args:
            config: Receiver configuration
            handler: Callback function for each received message
        """
        self.config = config
        self.handler = handler
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        """Start the syslog receiver."""
        loop = asyncio.get_running_loop()
        self._running = True

        if self.config.protocol in ("udp", "both"):
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: UDPSyslogProtocol(self.handler, self.config),
                local_addr=(self.config.bind_address, self.config.port),
            )
            self._udp_transport = transport
            logger.info(f"Syslog UDP listening on {self.config.bind_address}:{self.config.port}")

        if self.config.protocol in ("tcp", "both"):
            self._tcp_server = await loop.create_server(
                lambda: TCPSyslogProtocol(self.handler, self.config),
                self.config.bind_address,
                self.config.port,
            )
            logger.info(f"Syslog TCP listening on {self.config.bind_address}:{self.config.port}")

    async def stop(self) -> None:
        """Stop the syslog receiver."""
        self._running = False

        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
            logger.info("Syslog UDP stopped")

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
            logger.info("Syslog TCP stopped")

    @property
    def is_running(self) -> bool:
        """Check if the receiver is running."""
        return self._running

    async def run_forever(self) -> None:
        """Run the receiver until interrupted."""
        await self.start()

        # Set up signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            if stop_event.is_set():
                return  # Already shutting down, ignore repeated signals
            logger.info("Shutdown signal received")
            stop_event.set()

        # Register signal handlers
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                # Signal handlers not supported on this platform (e.g., Windows)
                pass

        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            # Replace signal handlers with no-ops instead of removing them.
            # Removing restores the default Python SIGINT handler which raises
            # KeyboardInterrupt — that would crash cleanup code still running
            # in the caller's finally block (DuckDB writes, flush, etc.).
            def _noop() -> None:
                pass
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _noop)
                except (NotImplementedError, ValueError):
                    pass
            await self.stop()
