"""What the gateway returns when a query is blocked.

Blocked queries are answered with a deliberate, well-formed DNS response - they
are never silently dropped. A dropped query looks like a network fault to the
client and makes the security control invisible; an explicit response code is
observable and debuggable.

Two policies are implemented and registered. ``SINKHOLE`` is declared but
deliberately **not** registered, because doing it properly needs per-record-type
answers (A, AAAA, and NODATA for everything else) and a configured sink address;
a half-working sinkhole is worse than an honest gap.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Type

import dns.flags
import dns.message
import dns.rcode

logger = logging.getLogger("dnssec.gateway.policy")


class BlockPolicy(ABC):
    """Builds the response returned for a blocked query."""

    name: str = "abstract"
    description: str = ""

    @abstractmethod
    def build_response(self, query: dns.message.Message) -> dns.message.Message:
        """Return the DNS message to send back to the client."""

    @staticmethod
    def _base_response(query: dns.message.Message) -> dns.message.Message:
        """A response echoing the query's id, question and RD flag."""
        response = dns.message.make_response(query)
        # We are answering authoritatively for a policy decision, and we are
        # not offering recursion beyond it.
        response.flags |= dns.flags.QR
        if query.flags & dns.flags.RD:
            response.flags |= dns.flags.RD | dns.flags.RA
        return response


class NXDomainPolicy(BlockPolicy):
    """Answer NXDOMAIN - the domain is reported as not existing.

    The most widely compatible block response: resolvers and applications
    handle it without hanging or retrying, and it fails closed.
    """

    name = "NXDOMAIN"
    description = "Return NXDOMAIN (name does not exist) for blocked domains."

    def build_response(self, query: dns.message.Message) -> dns.message.Message:
        response = self._base_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response


class RefusedPolicy(BlockPolicy):
    """Answer REFUSED - the server declines to answer.

    More honest than NXDOMAIN (the name may well exist; we are refusing), but
    some clients retry aggressively against other resolvers when they see it.
    """

    name = "REFUSED"
    description = "Return REFUSED for blocked domains."

    def build_response(self, query: dns.message.Message) -> dns.message.Message:
        response = self._base_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response


class SinkholePolicy(BlockPolicy):
    """PLANNED - redirect blocked domains to a controlled sink address.

    Not registered and not usable. Implementing it correctly requires a
    configured IPv4 and IPv6 sink address, correct NODATA responses for query
    types that are neither A nor AAAA, and a decision about what the sink host
    does with the traffic it receives. Left as a declared extension point
    rather than shipped half-working.
    """

    name = "SINKHOLE"
    description = "PLANNED - not implemented."

    def build_response(self, query: dns.message.Message) -> dns.message.Message:
        raise NotImplementedError(
            "SINKHOLE is a planned policy and is not implemented. Use NXDOMAIN "
            "or REFUSED via DNS_BLOCK_MODE."
        )


REGISTRY: Dict[str, Type[BlockPolicy]] = {
    NXDomainPolicy.name: NXDomainPolicy,
    RefusedPolicy.name: RefusedPolicy,
}

DECLARED_BUT_UNIMPLEMENTED = {SinkholePolicy.name: SinkholePolicy.description}


def get_policy(mode: str) -> BlockPolicy:
    """Resolve a configured mode name to a policy instance.

    Falls back to NXDOMAIN with a warning rather than failing to start - a
    typo in configuration should not leave the gateway unable to block.
    """
    key = (mode or "").strip().upper()
    policy_class = REGISTRY.get(key)
    if policy_class is None:
        logger.warning(
            "Unknown DNS_BLOCK_MODE %r; falling back to NXDOMAIN. Available: %s",
            mode,
            ", ".join(sorted(REGISTRY)),
        )
        policy_class = NXDomainPolicy
    return policy_class()
