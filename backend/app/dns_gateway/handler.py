"""The DNS request flow.

    packet -> parse question -> normalise -> EXISTING ANALYSIS ENGINE
           -> risk decision -> block OR (cache -> upstream) -> log -> response

The security decision happens **before** any upstream traffic. There is exactly
one call site for the resolver in this module, and it sits on the far side of
the decision branch, so no code path can forward a query that was not first
analysed.

The analysis itself is not reimplemented here. ``AnalysisPipeline`` is the same
object the ``/api/analyze`` endpoint uses, imported unchanged.
"""

import ipaddress
import logging
import time
from typing import Optional, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from ..core.normalizer import DomainValidationError
from ..core.pipeline import AnalysisPipeline
from .cache import DNSCache
from .models import DNSContext
from .policy import BlockPolicy
from .resolver import UpstreamError, UpstreamResolver

logger = logging.getLogger("dnssec.gateway.handler")

# Minimum bytes for a DNS header. Below this we cannot even recover a
# transaction id, so there is nothing meaningful to reply to.
DNS_HEADER_SIZE = 12


def _rcode_of(wire: bytes) -> str:
    """Response code carried by a DNS message, for logging only.

    Used on both the upstream and cache paths so one query is reported the
    same way regardless of which served it.
    """
    try:
        return dns.rcode.to_text(dns.message.from_wire(wire).rcode())
    except dns.exception.DNSException:
        return "UNKNOWN"


class DNSRequestHandler:
    """Turns a DNS query packet into a policy-controlled DNS response."""

    def __init__(
        self,
        pipeline: AnalysisPipeline,
        resolver: UpstreamResolver,
        policy: BlockPolicy,
        cache: DNSCache,
        repository=None,
        upstream_timeout: float = 3.0,
        log_client_ip: str = "loopback_only",
        stats=None,
    ) -> None:
        self.pipeline = pipeline
        self.resolver = resolver
        self.policy = policy
        self.cache = cache
        self.repository = repository
        self.upstream_timeout = upstream_timeout
        self.log_client_ip = log_client_ip
        self.stats = stats

    # -- privacy ------------------------------------------------------------

    def _client_address(self, addr: Optional[Tuple[str, int]]) -> Optional[str]:
        """Apply the configured client-address policy.

        Defaults to recording loopback addresses only, so a local prototype
        stays useful without accumulating the network addresses of real users.
        """
        if not addr or self.log_client_ip == "none":
            return None
        host = addr[0]
        if self.log_client_ip == "always":
            return host
        try:
            if ipaddress.ip_address(host).is_loopback:
                return host
        except ValueError:
            return None
        return None

    # -- entry point --------------------------------------------------------

    async def handle(
        self, data: bytes, addr: Optional[Tuple[str, int]] = None
    ) -> Optional[bytes]:
        """Process one DNS query packet and return the response bytes."""
        started = time.perf_counter()

        if len(data) < DNS_HEADER_SIZE:
            self._count("malformed_packets")
            logger.debug("Dropping runt packet of %d bytes", len(data))
            return None

        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException as exc:
            # We have a header, so we can at least answer FORMERR rather than
            # leaving the client waiting for a timeout.
            self._count("malformed_packets")
            logger.debug("Malformed DNS message: %s", exc)
            return self._error_from_raw(data, dns.rcode.FORMERR)

        if query.opcode() != dns.opcode.QUERY or not query.question:
            return self._error(query, dns.rcode.NOTIMP if query.question else dns.rcode.FORMERR)

        question = query.question[0]
        qname = question.name.to_text(omit_final_dot=True)
        qtype = dns.rdatatype.to_text(question.rdtype)
        qclass = dns.rdataclass.to_text(question.rdclass)

        context = DNSContext(
            query_type=qtype,
            query_class=qclass,
            client_address=self._client_address(addr),
        )
        if self.stats:
            self.stats.record_query_type(qtype)

        # -- 1. analysis, before anything touches the network ---------------
        # The record type is passed through as context: the tunnelling detector
        # uses it (TXT/NULL carry more return data and are favoured for covert
        # channels), and signals that do not care simply ignore it.
        try:
            result = self.pipeline.analyse(
                qname,
                {
                    "query_type": qtype,
                    "query_class": qclass,
                    # Already filtered by the privacy policy above, so what is
                    # forwarded is what was recorded - never the raw address.
                    "client_address": context.client_address,
                },
            )
        except DomainValidationError as exc:
            # A syntactically valid DNS name our normaliser rejects. Refuse
            # rather than forwarding something we could not evaluate.
            logger.debug("Rejecting unanalysable name %r: %s", qname, exc.code)
            context.blocked = True
            context.response_code = "REFUSED"
            context.total_gateway_time_ms = (time.perf_counter() - started) * 1000.0
            self._count("blocked")
            return self._to_wire(self._error(query, dns.rcode.REFUSED))

        context.analysis_time_ms = result.total_ms
        decision = result.assessment.decision

        # -- 2. act on the decision -----------------------------------------
        if decision == "BLOCK":
            response = self.policy.build_response(query)
            context.blocked = True
            context.block_policy = self.policy.name
            context.response_code = dns.rcode.to_text(response.rcode())
            self._count("blocked")
        else:
            response_wire, context = await self._resolve(query, question, context)
            self._count("monitored" if decision == "MONITOR" else "allowed")
            context.total_gateway_time_ms = (time.perf_counter() - started) * 1000.0
            self._log(result, context)
            return response_wire

        context.total_gateway_time_ms = (time.perf_counter() - started) * 1000.0
        self._log(result, context)
        return self._to_wire(response)

    # -- resolution ---------------------------------------------------------

    async def _resolve(self, query, question, context: DNSContext):
        """Serve from cache, else forward upstream. Only reached after ALLOW."""
        key = self.cache.key_for(
            question.name.to_text(omit_final_dot=True),
            question.rdtype,
            question.rdclass,
        )

        cached = self.cache.get(key, query.id)
        if cached is not None:
            context.cache_hit = True
            # Read the rcode back off the cached wire rather than assuming
            # NOERROR. A cached NXDOMAIN is still an NXDOMAIN: the client was
            # always served the correct bytes, but recording it as NOERROR
            # misreported the same query differently depending on whether it
            # happened to hit the cache, which corrupts the response-code
            # analytics.
            context.response_code = _rcode_of(cached)
            self._count("cache_hits")
            return cached, context

        upstream_started = time.perf_counter()
        try:
            response_wire = await self.resolver.resolve(
                query.to_wire(), self.upstream_timeout
            )
            self._count("upstream_queries")
        except UpstreamError as exc:
            # The gateway stays up and tells the client the truth: we could not
            # resolve this. It does not invent an answer.
            context.dns_upstream_time_ms = (time.perf_counter() - upstream_started) * 1000.0
            context.response_code = "SERVFAIL"
            context.upstream_used = True
            self._count("upstream_failures")
            logger.warning("Upstream resolution failed: %s", exc)
            return self._to_wire(self._error(query, dns.rcode.SERVFAIL)), context

        context.dns_upstream_time_ms = (time.perf_counter() - upstream_started) * 1000.0
        context.upstream_used = True
        self.cache.put(key, response_wire)
        context.response_code = _rcode_of(response_wire)

        return response_wire, context

    # -- helpers ------------------------------------------------------------

    def _count(self, field: str) -> None:
        if self.stats is not None:
            setattr(self.stats, field, getattr(self.stats, field, 0) + 1)

    @staticmethod
    def _to_wire(message: dns.message.Message) -> bytes:
        return message.to_wire()

    @staticmethod
    def _error(query: dns.message.Message, rcode: int) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        return response

    @staticmethod
    def _error_from_raw(data: bytes, rcode: int) -> Optional[bytes]:
        """Build a minimal error response when the query would not parse.

        Only the transaction id is trustworthy, so we echo it with QR set, the
        given rcode, and all section counts zeroed.
        """
        try:
            transaction_id = data[0:2]
            flags = (0x8000 | (rcode & 0x000F)).to_bytes(2, "big")
            return transaction_id + flags + (b"\x00\x00" * 4)
        except Exception:
            return None

    def _log(self, result, context: DNSContext) -> None:
        """Persist the DNS security event. Never fails the query."""
        if self.repository is None:
            return
        try:
            self.repository.log(result, source="dns", dns=context)
        except Exception:
            logger.exception("Failed to persist DNS event")
