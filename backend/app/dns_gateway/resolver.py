"""Upstream DNS resolution.

The gateway forwards the client's **original query bytes** and returns the
upstream's **raw response bytes**. We parse the query to inspect the question,
but we never re-serialise a response we did not author. That avoids an entire
class of bugs around name compression, EDNS0 and unusual RDATA, and makes this
a genuine forwarder rather than a partial reimplementation of DNS.

Security note: the gateway resolves through the configured upstream resolver
and does nothing else with a queried domain. It never issues HTTP requests to
it, never fetches content from it, and never connects to it directly.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("dnssec.gateway.resolver")


class UpstreamError(RuntimeError):
    """Upstream resolution failed - timeout, refusal, or transport error."""


class UpstreamResolver(ABC):
    """Any source of upstream DNS answers."""

    @abstractmethod
    async def resolve(self, query_wire: bytes, timeout: float) -> bytes:
        """Send a raw DNS query and return the raw response.

        Must raise ``UpstreamError`` on failure rather than returning a
        fabricated answer.
        """

    @abstractmethod
    def describe(self) -> Dict[str, Any]:
        """Provenance for the health endpoint and dashboard."""


class _UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: "asyncio.Future") -> None:
        self.future = future

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(UpstreamError(str(exc)))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if not self.future.done() and exc is not None:
            self.future.set_exception(UpstreamError(str(exc)))


class UDPUpstreamResolver(UpstreamResolver):
    """Forwards queries to a configured resolver over UDP."""

    def __init__(self, host: str, port: int = 53) -> None:
        self.host = host
        self.port = port

    async def resolve(self, query_wire: bytes, timeout: float) -> bytes:
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UpstreamProtocol(future),
                remote_addr=(self.host, self.port),
            )
            transport.sendto(query_wire)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            raise UpstreamError(
                "Upstream {}:{} did not respond within {}s".format(
                    self.host, self.port, timeout
                )
            )
        except UpstreamError:
            raise
        except OSError as exc:
            raise UpstreamError(
                "Could not reach upstream {}:{}: {}".format(self.host, self.port, exc)
            )
        finally:
            if transport is not None:
                transport.close()

    def describe(self) -> Dict[str, Any]:
        return {
            "type": "udp",
            "address": "{}:{}".format(self.host, self.port),
            "host": self.host,
            "port": self.port,
        }


class StubUpstreamResolver(UpstreamResolver):
    """Deterministic upstream for tests.

    Records every call, so a test can assert that a BLOCKED query produced
    **no** upstream traffic at all - which is the property that matters.
    """

    def __init__(
        self,
        responder=None,
        fail: bool = False,
        delay: float = 0.0,
    ) -> None:
        self.calls: List[bytes] = []
        self.responder = responder
        self.fail = fail
        self.delay = delay

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def resolve(self, query_wire: bytes, timeout: float) -> bytes:
        self.calls.append(query_wire)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise UpstreamError("stub upstream configured to fail")
        if self.responder is None:
            raise UpstreamError("stub upstream has no responder configured")
        return self.responder(query_wire)

    def describe(self) -> Dict[str, Any]:
        return {"type": "stub", "address": "stub://test", "calls": self.call_count}
