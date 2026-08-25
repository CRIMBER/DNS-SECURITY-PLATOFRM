"""UDP DNS server.

An ``asyncio`` datagram endpoint that receives real DNS packets and hands each
one to the request handler. The server owns the socket and the process-level
counters; it knows nothing about security policy.

Both UDP and TCP are served. They share one handler, one analysis pipeline and
one policy; only the framing differs (see ``tcp.py``).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from .models import GatewayStats
from .tcp import DNSTCPServer

logger = logging.getLogger("dnssec.gateway")


class DNSServerProtocol(asyncio.DatagramProtocol):
    """Receives datagrams and dispatches them without blocking the loop."""

    def __init__(self, gateway: "DNSGateway") -> None:
        self.gateway = gateway
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        # Handling is awaited separately so a slow upstream never stalls
        # reception of other queries.
        asyncio.ensure_future(self._dispatch(data, addr))

    async def _dispatch(self, data: bytes, addr: Tuple[str, int]) -> None:
        stats = self.gateway.stats
        stats.queries_received += 1
        try:
            response = await self.gateway.handler.handle(data, addr)
        except Exception:
            # A handler bug must never take the server down.
            stats.handler_errors += 1
            logger.exception("Unhandled error while processing a DNS query")
            response = None

        if response and self.transport is not None:
            try:
                self.transport.sendto(response, addr)
                stats.queries_answered += 1
            except OSError:
                logger.exception("Failed to send DNS response to %s", addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("DNS socket error: %s", exc)


class DNSGatewayBindError(RuntimeError):
    """Raised when the listen address cannot be bound."""


class DNSGateway:
    """Owns the listening socket and the gateway's lifecycle."""

    def __init__(
        self, handler, host: str, port: int, tcp_enabled: bool = True
    ) -> None:
        self.handler = handler
        self.host = host
        self.port = port
        self.stats = GatewayStats()
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[DNSServerProtocol] = None
        self.bind_error: Optional[str] = None
        self.tcp_enabled = tcp_enabled
        self.tcp: Optional[DNSTCPServer] = None

    @property
    def running(self) -> bool:
        return self.transport is not None

    @property
    def listen_address(self) -> str:
        return "{}:{}".format(self.host, self.port)

    async def start(self) -> None:
        """Bind the UDP socket. Raises ``DNSGatewayBindError`` on failure."""
        if self.running:
            return
        loop = asyncio.get_event_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DNSServerProtocol(self),
                local_addr=(self.host, self.port),
            )
        except OSError as exc:
            # Port 5353 is also mDNS/Bonjour and may already be in use.
            self.bind_error = (
                "Could not bind {}: {}. Port 5353 is also used by mDNS/Bonjour; "
                "set DNS_LISTEN_PORT to a free port (for example 5354) and "
                "restart.".format(self.listen_address, exc)
            )
            logger.error(self.bind_error)
            raise DNSGatewayBindError(self.bind_error)

        self.transport = transport
        self.protocol = protocol
        self.bind_error = None
        self.stats.started_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # Report the address actually bound - it differs from the requested one
        # when port 0 was used to get an ephemeral port (as tests do).
        bound = transport.get_extra_info("sockname")
        if bound:
            self.host, self.port = bound[0], bound[1]
        logger.info("DNS gateway listening on %s/udp", self.listen_address)

        # TCP is best-effort: a client that cannot use it still gets UDP, so a
        # TCP bind failure must not take the gateway down. It is reported
        # through status() rather than swallowed.
        if self.tcp_enabled:
            self.tcp = DNSTCPServer(self, self.host, self.port)
            try:
                await self.tcp.start()
            except OSError:
                logger.warning(
                    "UDP is serving but TCP could not bind; truncated-response "
                    "retries and TCP-only clients will not be handled."
                )

    async def stop(self) -> None:
        if self.tcp is not None:
            await self.tcp.stop()
            self.tcp = None
        if self.transport is not None:
            self.transport.close()
            self.transport = None
            self.protocol = None
            logger.info("DNS gateway stopped")

    def status(self) -> dict:
        """Everything the dashboard needs to describe the gateway honestly."""
        protocols = []
        if self.running:
            protocols.append("udp")
        if self.tcp is not None and self.tcp.running:
            protocols.append("tcp")

        return {
            "running": self.running,
            "listen_address": self.listen_address if self.running else None,
            "protocol": "+".join(protocols) if protocols else "none",
            "tcp": {
                "enabled": self.tcp_enabled,
                "running": bool(self.tcp and self.tcp.running),
                "connections": self.tcp.connections if self.tcp else 0,
                "bind_error": self.tcp.bind_error if self.tcp else None,
            },
            "bind_error": self.bind_error,
            "upstream": self.handler.resolver.describe() if self.handler else None,
            "block_policy": self.handler.policy.name if self.handler else None,
            "cache": self.handler.cache.stats() if self.handler else None,
            "stats": self.stats.to_dict(),
        }
