"""DNS over TCP.

UDP carries most DNS, but TCP is not optional in practice: a resolver that
receives a truncated response (TC bit set) is required to retry over TCP, and
some clients go straight to TCP. A gateway that only speaks UDP silently fails
those queries, which is a security hole as much as a compatibility one - a
client that cannot reach us may fall back to a resolver that applies no policy
at all.

The framing difference from UDP is the whole of it: RFC 1035 s4.2.2 prefixes
each message with a two-octet big-endian length. Everything after that framing
is the same handler, the same analysis and the same policy as the UDP path -
this module deliberately contains no security logic of its own.
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("dnssec.gateway.tcp")

LENGTH_PREFIX_SIZE = 2
MAX_MESSAGE_SIZE = 65535
# A client that connects and then says nothing must not hold a slot forever.
READ_TIMEOUT_SECONDS = 5.0


class DNSTCPServer:
    """Accepts DNS over TCP and delegates to the shared request handler."""

    def __init__(self, gateway, host: str, port: int) -> None:
        self.gateway = gateway
        self.host = host
        self.port = port
        self.server: Optional[asyncio.AbstractServer] = None
        self.bind_error: Optional[str] = None
        self.connections = 0

    @property
    def running(self) -> bool:
        return self.server is not None

    async def start(self) -> None:
        try:
            self.server = await asyncio.start_server(
                self._handle_connection, self.host, self.port
            )
        except OSError as exc:
            self.bind_error = "Could not bind TCP {}:{}: {}".format(
                self.host, self.port, exc
            )
            logger.warning(self.bind_error)
            raise

        # Reflect the actually-bound port, which differs when port 0 was asked
        # for to get an ephemeral one.
        sockets = self.server.sockets or []
        if sockets:
            self.host, self.port = sockets[0].getsockname()[:2]
        self.bind_error = None
        logger.info("DNS gateway listening on %s:%s/tcp", self.host, self.port)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:  # pragma: no cover - shutdown race
                pass
            self.server = None
            logger.info("DNS TCP listener stopped")

    async def _handle_connection(self, reader, writer) -> None:
        """Serve one TCP connection.

        A single connection may carry several queries back to back, so we loop
        until the peer closes it or goes quiet.
        """
        self.connections += 1
        peer = writer.get_extra_info("peername")
        try:
            while True:
                try:
                    header = await asyncio.wait_for(
                        reader.readexactly(LENGTH_PREFIX_SIZE),
                        timeout=READ_TIMEOUT_SECONDS,
                    )
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    return  # peer finished or went idle; both are normal

                length = int.from_bytes(header, "big")
                if length == 0 or length > MAX_MESSAGE_SIZE:
                    logger.debug("Rejecting TCP message claiming %d bytes", length)
                    return

                try:
                    payload = await asyncio.wait_for(
                        reader.readexactly(length), timeout=READ_TIMEOUT_SECONDS
                    )
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    # The length prefix promised more than arrived.
                    self.gateway.stats.malformed_packets += 1
                    return

                self.gateway.stats.queries_received += 1
                try:
                    response = await self.gateway.handler.handle(payload, peer)
                except Exception:
                    self.gateway.stats.handler_errors += 1
                    logger.exception("Unhandled error on a TCP DNS query")
                    return

                if not response:
                    return

                writer.write(len(response).to_bytes(LENGTH_PREFIX_SIZE, "big"))
                writer.write(response)
                await writer.drain()
                self.gateway.stats.queries_answered += 1
        except (ConnectionResetError, BrokenPipeError):
            pass  # client hung up mid-exchange; nothing to do
        except Exception:  # pragma: no cover - defensive
            logger.exception("TCP connection handler failed")
        finally:
            try:
                writer.close()
            except Exception:
                pass
