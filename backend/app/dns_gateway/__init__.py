"""DNS security gateway.

Places a real DNS server in front of the existing analysis engine. The engine
is imported unchanged - no detection logic is duplicated here.

The gateway is constructed from settings and exposed as a process-level
singleton, mirroring how ``intel`` and ``detection`` expose theirs.
"""

from typing import Optional

from ..config import Settings, get_settings
from ..core.pipeline import get_pipeline
from .cache import DNSCache
from .handler import DNSRequestHandler
from .models import DNSContext, GatewayStats
from .policy import BlockPolicy, NXDomainPolicy, RefusedPolicy, get_policy
from .resolver import (
    StubUpstreamResolver,
    UDPUpstreamResolver,
    UpstreamError,
    UpstreamResolver,
)
from .server import DNSGateway, DNSGatewayBindError
from .tcp import DNSTCPServer

__all__ = [
    "DNSCache",
    "DNSContext",
    "DNSGateway",
    "DNSGatewayBindError",
    "DNSTCPServer",
    "DNSRequestHandler",
    "GatewayStats",
    "BlockPolicy",
    "NXDomainPolicy",
    "RefusedPolicy",
    "get_policy",
    "UpstreamResolver",
    "UDPUpstreamResolver",
    "StubUpstreamResolver",
    "UpstreamError",
    "build_gateway",
    "get_gateway",
    "set_gateway",
]

_gateway: Optional[DNSGateway] = None


def build_gateway(
    settings: Optional[Settings] = None,
    resolver: Optional[UpstreamResolver] = None,
    repository=None,
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> DNSGateway:
    """Assemble a gateway from settings.

    ``resolver``, ``repository``, ``host`` and ``port`` can be overridden so
    tests can run a real gateway on an ephemeral port against a stub upstream,
    with no internet access and no shared state.
    """
    settings = settings or get_settings()

    if repository is None:
        from ..storage.events import get_event_repository

        repository = get_event_repository()

    if resolver is None:
        resolver = UDPUpstreamResolver(
            settings.upstream_dns_host, settings.upstream_dns_port
        )

    cache = DNSCache(
        enabled=settings.dns_cache_enabled,
        max_entries=settings.dns_cache_max_entries,
        max_ttl=settings.dns_cache_max_ttl,
    )

    stats = GatewayStats()
    handler = DNSRequestHandler(
        pipeline=get_pipeline(),
        resolver=resolver,
        policy=get_policy(settings.dns_block_mode),
        cache=cache,
        repository=repository,
        upstream_timeout=settings.dns_upstream_timeout,
        log_client_ip=settings.dns_log_client_ip,
        stats=stats,
    )

    gateway = DNSGateway(
        handler=handler,
        host=settings.dns_listen_host if host is None else host,
        port=settings.dns_listen_port if port is None else port,
        tcp_enabled=settings.dns_tcp_enabled,
    )
    gateway.stats = stats
    handler.stats = stats
    return gateway


def get_gateway() -> Optional[DNSGateway]:
    """The running gateway, or None when it is disabled or not started."""
    return _gateway


def set_gateway(gateway: Optional[DNSGateway]) -> None:
    global _gateway
    _gateway = gateway
