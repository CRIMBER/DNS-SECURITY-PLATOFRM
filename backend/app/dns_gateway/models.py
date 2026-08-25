"""Shared types for the DNS gateway.

``DNSContext`` is the DNS-specific half of an event. The security half - risk
score, classification, decision, factors - comes from the existing
``AnalysisResult`` unchanged. The two are written to one row rather than to a
parallel table, so the dashboard sees a single unified event stream.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class DNSContext:
    """What happened at the DNS layer for one query."""

    query_type: str = "A"
    query_class: str = "IN"
    client_address: Optional[str] = None
    """Recorded according to the ``DNS_LOG_CLIENT_IP`` policy; may be None."""

    blocked: bool = False
    upstream_used: bool = False
    cache_hit: bool = False
    response_code: str = "NOERROR"
    block_policy: Optional[str] = None

    analysis_time_ms: float = 0.0
    """Time inside the existing analysis pipeline."""

    dns_upstream_time_ms: float = 0.0
    """Time waiting on the upstream resolver. Zero when blocked or cached."""

    total_gateway_time_ms: float = 0.0
    """Wire-to-wire: packet received to response ready. Always >= the other two."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_type": self.query_type,
            "query_class": self.query_class,
            "client_address": self.client_address,
            "blocked": self.blocked,
            "upstream_used": self.upstream_used,
            "cache_hit": self.cache_hit,
            "response_code": self.response_code,
            "block_policy": self.block_policy,
            "analysis_time_ms": round(self.analysis_time_ms, 3),
            "dns_upstream_time_ms": round(self.dns_upstream_time_ms, 3),
            "total_gateway_time_ms": round(self.total_gateway_time_ms, 3),
        }


@dataclass
class GatewayStats:
    """Live counters held in memory by the running gateway.

    These describe the *process*; historical figures come from the event store.
    """

    started_at: Optional[str] = None
    queries_received: int = 0
    queries_answered: int = 0
    allowed: int = 0
    monitored: int = 0
    blocked: int = 0
    cache_hits: int = 0
    upstream_queries: int = 0
    upstream_failures: int = 0
    malformed_packets: int = 0
    handler_errors: int = 0
    by_query_type: Dict[str, int] = field(default_factory=dict)

    def record_query_type(self, qtype: str) -> None:
        self.by_query_type[qtype] = self.by_query_type.get(qtype, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "queries_received": self.queries_received,
            "queries_answered": self.queries_answered,
            "allowed": self.allowed,
            "monitored": self.monitored,
            "blocked": self.blocked,
            "cache_hits": self.cache_hits,
            "upstream_queries": self.upstream_queries,
            "upstream_failures": self.upstream_failures,
            "malformed_packets": self.malformed_packets,
            "handler_errors": self.handler_errors,
            "by_query_type": dict(sorted(self.by_query_type.items())),
        }
