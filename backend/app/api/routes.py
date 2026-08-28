"""HTTP endpoints.

Step 2 exposes health plus a feature-inspection endpoint used to test and tune
the lexical engine. ``POST /api/analyze``, ``/api/events`` and ``/api/stats``
arrive in later steps once threat intelligence, the DGA detector, the risk
engine and persistence are in place - they are not stubbed out here, because a
fake endpoint is worse than a missing one.
"""

import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, Request

from ..capture import (
    CaptureQuery,
    PcapFormatError,
    ZeekFormatError,
    analyse_capture,
    extract_dns_queries,
    read_zeek_dns_log,
)
from ..capture.pcap import MAX_PACKETS as PCAP_MAX_PACKETS
from ..capture.report import MAX_UNIQUE_DOMAINS
from ..config import get_risk_config, get_settings
from ..core.features import BRANDS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLD_WEIGHTS, extract_features
from ..core.lexical import score_lexical
from ..core.normalizer import DomainValidationError, normalize
from ..core.pipeline import AnalysisResult, get_pipeline
from ..detection import (
    dga_to_signal,
    get_behavioral_analyzer,
    get_dga_detector,
    get_tunnel_detector,
)
from ..dns_gateway import get_gateway
from ..dns_gateway.policy import DECLARED_BUT_UNIMPLEMENTED, REGISTRY
from ..intel import get_threat_intel_provider, intel_to_signal
from ..schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BulkAnalyzeRequest,
    BulkAnalyzeResponse,
    DGAAnalysisResponse,
    EventsResponse,
    FeatureInspectionResponse,
    HealthResponse,
    DNSStatsResponse,
    DNSStatusResponse,
    IntelLookupResponse,
    StatsResponse,
)
from ..storage.events import get_event_repository

router = APIRouter()

# A capture arrives as a raw request body rather than a multipart form, so no
# extra dependency is needed to accept one. Uploads are bounded because a
# capture is untrusted input like any other.
MAX_UPLOAD_BYTES = 25_000_000


class CaptureUploadError(Exception):
    """A capture could not be read. Carries a code the dashboard can show."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Liveness plus what each pipeline component is currently backed by."""
    settings = get_settings()
    config = get_risk_config()

    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version=settings.version,
        risk_config_version=config.version,
        components={
            "normalizer": {"status": "ok"},
            "feature_extractor": {
                "status": "ok",
                "suspicious_tlds_loaded": len(SUSPICIOUS_TLD_WEIGHTS),
                "keywords_loaded": len(SUSPICIOUS_KEYWORDS),
                "brands_loaded": len(BRANDS),
            },
            "lexical_scorer": {
                "status": "ok",
                "method": "rule_based_lexical_v1",
                "type": "TRANSPARENT_RULE_BASED",
            },
            "threat_intelligence": dict(
                get_threat_intel_provider().stats(), status="ok"
            ),
            "dga_detector": dict(get_dga_detector().info(), status="ok"),
            "tunnel_detector": dict(get_tunnel_detector().info(), status="ok"),
            "behavioral_analyzer": dict(
                get_behavioral_analyzer().info(), status="ok"
            ),
            "risk_engine": {
                "status": "ok",
                "weights": config.weights,
                "bands": len(config.bands),
                "fusion": "confidence_weighted_average",
            },
            "dns_gateway": _dns_gateway_health(),
            "event_store": {
                "status": "ok",
                "backend": "sqlite",
                "events_stored": get_event_repository().stats()["total_analyzed"],
            },
        },
    )


@router.get("/config", tags=["system"])
async def read_config():
    """The active detection policy: weights, bands and override rules.

    Exposed deliberately - an analyst should be able to see the exact policy
    that produced a verdict.
    """
    return get_risk_config().public_view()


@router.post(
    "/debug/features",
    response_model=FeatureInspectionResponse,
    tags=["development"],
)
async def inspect_features(request: AnalyzeRequest) -> FeatureInspectionResponse:
    """Run normalisation + feature extraction + lexical scoring only.

    A tuning aid for the lexical rules. Creates no event and makes no decision.
    """
    started = time.perf_counter()

    normalized = normalize(request.domain)
    features = extract_features(normalized)
    signal = score_lexical(features)

    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return FeatureInspectionResponse(
        input=normalized.original_input,
        domain=normalized.domain,
        registrable_domain=normalized.registrable_domain,
        tld=normalized.tld,
        subdomain=normalized.subdomain,
        was_url=normalized.was_url,
        domain_features=features.to_dict(),
        lexical_score=round(signal.score, 2),
        lexical_confidence=signal.confidence,
        lexical_factors=[
            {
                "code": f.code,
                "label": f.label,
                "severity": f.severity.value,
                "detail": f.detail,
                "contribution": round(f.raw_points, 2),
            }
            for f in signal.factors
        ],
        extraction_time_ms=round(elapsed_ms, 3),
    )


@router.post(
    "/intel/lookup",
    response_model=IntelLookupResponse,
    tags=["threat-intelligence"],
)
async def intel_lookup(request: AnalyzeRequest) -> IntelLookupResponse:
    """Query threat intelligence for a domain in isolation.

    Returns this one signal only - no fusion, no decision. Useful for
    inspecting what the dataset knows and for verifying that an unknown domain
    yields confidence 0.0 rather than a low-risk verdict.
    """
    started = time.perf_counter()

    normalized = normalize(request.domain)
    provider = get_threat_intel_provider()
    result = provider.lookup(normalized.domain, normalized.registrable_domain)
    signal = intel_to_signal(result, get_risk_config())

    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return IntelLookupResponse(
        domain=normalized.domain,
        registrable_domain=normalized.registrable_domain,
        threat_intelligence=result.to_dict(),
        signal_score=signal.score,
        signal_confidence=signal.confidence,
        lookup_time_ms=round(elapsed_ms, 3),
    )


@router.post("/debug/dga", response_model=DGAAnalysisResponse, tags=["detection"])
async def analyse_dga(request: AnalyzeRequest) -> DGAAnalysisResponse:
    """Run DGA / suspicion analysis on a domain in isolation.

    Returns this one signal only - no fusion, no decision.
    """
    started = time.perf_counter()

    normalized = normalize(request.domain)
    features = extract_features(normalized)
    detector = get_dga_detector()
    result = detector.analyse(features)
    signal = dga_to_signal(result, get_risk_config())

    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return DGAAnalysisResponse(
        domain=normalized.domain,
        registrable_domain=normalized.registrable_domain,
        analysed_label=features.sld,
        dga_analysis=result.to_dict(),
        signal_score=round(signal.score, 2),
        signal_confidence=signal.confidence,
        analysis_time_ms=round(elapsed_ms, 3),
    )


# -- the main analysis endpoint --------------------------------------------


def _to_response(result: AnalysisResult, event_id) -> AnalyzeResponse:
    """Shape a pipeline result into the public API contract."""
    assessment = result.assessment
    return AnalyzeResponse(
        domain=result.normalized.domain,
        registrable_domain=result.normalized.registrable_domain,
        risk_score=assessment.score,
        classification=assessment.classification,
        decision=assessment.decision,
        confidence=round(assessment.confidence, 3),
        threat_intelligence=result.intel_metadata,
        dga_analysis=result.dga_metadata,
        tunnel_analysis=result.tunnel_metadata,
        behavioral_analysis=result.behavioral_metadata,
        domain_features=result.features.to_dict(),
        risk_factors=[f.to_dict() for f in assessment.factors],
        signals=[s.to_dict() for s in assessment.signals],
        overrides_applied=assessment.overrides_applied,
        recommended_action=assessment.recommended_action,
        analysis_time_ms=result.total_ms,
        stage_timings_ms=result.timings_ms,
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


@router.post("/analyze", response_model=AnalyzeResponse, tags=["analysis"])
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyse a domain end to end and persist the result as an event.

    Runs normalisation, feature extraction, all three signals and risk fusion,
    then returns the decision together with the factors that produced it.
    """
    result = get_pipeline().analyse(request.domain)
    event_id = get_event_repository().log(result, source=request.source)
    return _to_response(result, event_id)


@router.post("/analyze/bulk", response_model=BulkAnalyzeResponse, tags=["analysis"])
async def analyze_bulk(request: BulkAnalyzeRequest) -> BulkAnalyzeResponse:
    """Analyse several domains in one call.

    Invalid entries are reported individually rather than failing the batch.
    """
    started = time.perf_counter()
    pipeline = get_pipeline()
    repository = get_event_repository()

    results = []
    errors = []
    for domain in request.domains:
        try:
            result = pipeline.analyse(domain)
            event_id = repository.log(result, source=request.source)
            results.append(_to_response(result, event_id))
        except DomainValidationError as exc:
            errors.append(
                {"domain": str(domain), "code": exc.code, "message": exc.message}
            )

    return BulkAnalyzeResponse(
        analyzed=len(results),
        failed=len(errors),
        results=results,
        errors=errors,
        total_time_ms=round((time.perf_counter() - started) * 1000.0, 3),
    )


# -- events and statistics --------------------------------------------------


@router.get("/events", response_model=EventsResponse, tags=["events"])
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    classification: Optional[str] = Query(
        None, description="SAFE | SUSPICIOUS | MALICIOUS"
    ),
    decision: Optional[str] = Query(None, description="ALLOW | MONITOR | BLOCK"),
    q: Optional[str] = Query(None, description="Substring match on the domain."),
    event_type: Optional[str] = Query(
        None, description="analysis | dns. Omit for both."
    ),
) -> EventsResponse:
    """Recent events, newest first. Covers both analysis and DNS events."""
    return EventsResponse(
        **get_event_repository().list_events(
            limit=limit,
            offset=offset,
            classification=classification,
            decision=decision,
            query=q,
            event_type=event_type,
        )
    )


@router.get("/stats", response_model=StatsResponse, tags=["events"])
async def stats() -> StatsResponse:
    """Aggregate statistics computed from stored events."""
    return StatsResponse(**get_event_repository().stats())


@router.delete("/events", tags=["events"])
async def clear_events():
    """Delete every stored event.

    Provided so a demo can be reset to a clean state. It is an explicit,
    clearly-named destructive operation rather than a hidden one.
    """
    deleted = get_event_repository().clear()
    return {"deleted": deleted, "message": "Event log cleared."}


# -- DNS gateway ------------------------------------------------------------


def _dns_gateway_health() -> dict:
    """Honest gateway state for /api/health.

    Reports 'disabled', 'error' or 'ok' - never 'ok' for a gateway that is not
    actually bound to a socket.
    """
    settings = get_settings()
    gateway = get_gateway()

    if not settings.dns_enabled:
        return {"status": "disabled", "reason": "DNS_ENABLED=false"}
    if gateway is None:
        return {
            "status": "not_started",
            "reason": "The gateway starts with the ASGI lifespan; it does not "
                      "run under the test client or an imported app.",
        }
    if not gateway.running:
        return {"status": "error", "reason": gateway.bind_error}
    return {
        "status": "ok",
        "listen_address": gateway.listen_address,
        "protocol": gateway.status()["protocol"],
        "upstream": gateway.handler.resolver.describe()["address"],
        "block_policy": gateway.handler.policy.name,
        "queries_received": gateway.stats.queries_received,
        "blocked": gateway.stats.blocked,
    }


@router.get("/dns/status", response_model=DNSStatusResponse, tags=["dns"])
async def dns_status() -> DNSStatusResponse:
    """Live DNS gateway state: listener, upstream, policy, cache and counters."""
    settings = get_settings()
    gateway = get_gateway()

    base = {
        "enabled": settings.dns_enabled,
        "available_block_policies": sorted(REGISTRY),
        "unimplemented_block_policies": DECLARED_BUT_UNIMPLEMENTED,
    }

    if gateway is None:
        return DNSStatusResponse(
            running=False,
            bind_error=None if settings.dns_enabled else "Gateway is disabled.",
            **base
        )

    status = gateway.status()
    return DNSStatusResponse(
        running=status["running"],
        listen_address=status["listen_address"],
        protocol=status["protocol"],
        tcp=status.get("tcp", {}),
        bind_error=status["bind_error"],
        upstream=status["upstream"],
        block_policy=status["block_policy"],
        cache=status["cache"],
        stats=status["stats"],
        **base
    )


@router.get("/dns/stats", response_model=DNSStatsResponse, tags=["dns"])
async def dns_stats() -> DNSStatsResponse:
    """Statistics over DNS gateway events, computed from stored events."""
    return DNSStatsResponse(**get_event_repository().dns_stats())


@router.get("/dns/events", response_model=EventsResponse, tags=["dns"])
async def dns_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="ALLOW | MONITOR | BLOCK"),
    q: Optional[str] = Query(None, description="Substring match on the domain."),
) -> EventsResponse:
    """Recent DNS gateway events only, newest first."""
    return EventsResponse(
        **get_event_repository().list_events(
            limit=limit, offset=offset, decision=decision, query=q, event_type="dns"
        )
    )


# -- source telemetry --------------------------------------------------------


@router.get("/sources", tags=["dns"])
async def source_ips(limit: int = Query(50, ge=1, le=500)):
    """Query volume and block rate per client address.

    Real telemetry from the gateway's own event log, not a projection. What
    it can show depends on the ``dns_log_client_ip`` setting, which is
    reported alongside the rows so the numbers are read in the right light:
    ``loopback_only`` (the default) records an address only for local
    clients, ``always`` records every client, ``none`` records none.
    """
    settings = get_settings()
    payload = get_event_repository().source_ip_stats(limit=limit)
    payload["client_ip_logging"] = settings.dns_log_client_ip
    payload["note"] = {
        "none": "Client addresses are not recorded, so no source can be "
                "attributed. Set DNS_LOG_CLIENT_IP=always to enable.",
        "loopback_only": "Only loopback clients have their address recorded "
                         "(the default). A deployment serving real clients "
                         "sets DNS_LOG_CLIENT_IP=always.",
        "always": "Every client address is recorded.",
    }.get(settings.dns_log_client_ip, "")
    return payload


# -- capture analysis --------------------------------------------------------


@router.get("/capture/support", tags=["capture"])
async def capture_support():
    """What the offline readers actually handle. Stated, not implied."""
    return {
        "pcap": {
            "status": "IMPLEMENTED",
            "formats": ["libpcap (classic)", "pcapng"],
            "link_types": ["Ethernet", "raw IP", "Linux SLL",
                           "Linux SLL2", "null/loopback"],
            "network": ["IPv4", "IPv6"],
            "transport": ["UDP/53", "TCP/53 (first segment)"],
            "parser": "dnspython wire-format parsing - the library the gateway uses",
            "max_packets": PCAP_MAX_PACKETS,
        },
        "zeek": {
            "status": "IMPLEMENTED",
            "formats": ["dns.log TSV (#fields header)"],
            "not_supported": ["Zeek JSON output"],
            "columns_used": ["ts", "id.orig_h", "id.resp_h", "query",
                             "qtype_name", "rcode_name"],
        },
        "analysis": {
            "engine": "the same pipeline used by /api/analyze and the resolver",
            "max_unique_domains": MAX_UNIQUE_DOMAINS,
            "writes_to_event_log": False,
            "note": "Capture verdicts are not written to the event store. A "
                    "capture is another network's traffic; recording it as this "
                    "resolver's history would corrupt the behavioural detector, "
                    "which scores a domain by what it has done here.",
        },
        "max_upload_bytes": MAX_UPLOAD_BYTES,
    }


async def _read_upload(request: Request) -> bytes:
    body = await request.body()
    if not body:
        raise CaptureUploadError("EMPTY_UPLOAD", "No file content was received.")
    if len(body) > MAX_UPLOAD_BYTES:
        raise CaptureUploadError(
            "UPLOAD_TOO_LARGE",
            "The capture is {:.1f} MB; the limit is {:.0f} MB.".format(
                len(body) / 1e6, MAX_UPLOAD_BYTES / 1e6
            ),
        )
    return body


@router.post("/capture/pcap", tags=["capture"])
async def analyse_pcap(request: Request):
    """Extract DNS queries from a packet capture and score every unique name.

    The request body is the raw file. Every verdict comes from the pipeline
    that serves ``/api/analyze``; nothing here re-implements detection.
    """
    body = await _read_upload(request)
    try:
        found = extract_dns_queries(body)
    except PcapFormatError as exc:
        raise CaptureUploadError("INVALID_PCAP", str(exc))

    report = analyse_capture(
        [
            CaptureQuery(
                domain=q.domain, query_type=q.query_type, source_ip=q.source_ip,
                dest_ip=q.dest_ip, timestamp=q.timestamp,
                is_response=q.is_response,
            )
            for q in found
        ],
        origin="pcap",
    )
    report["capture_bytes"] = len(body)
    report["dns_packets_seen"] = len(found)
    return report


@router.post("/capture/zeek", tags=["capture"])
async def analyse_zeek(request: Request):
    """Read a Zeek dns.log (TSV) and score every unique query it recorded."""
    body = await _read_upload(request)
    try:
        rows = read_zeek_dns_log(body)
    except ZeekFormatError as exc:
        raise CaptureUploadError("INVALID_ZEEK_LOG", str(exc))

    report = analyse_capture(
        [
            CaptureQuery(
                domain=r.domain, query_type=r.query_type, source_ip=r.source_ip,
                dest_ip=r.dest_ip, timestamp=r.timestamp,
                extra={"rcode": r.rcode} if r.rcode else {},
            )
            for r in rows
        ],
        origin="zeek",
    )
    report["capture_bytes"] = len(body)
    report["log_rows"] = len(rows)
    return report


# -- threat intelligence -----------------------------------------------------


@router.get("/intel/summary", tags=["intel"])
async def intel_summary():
    """What the threat-intelligence layer is actually backed by.

    Feed connectivity is reported as it is, not as a product sheet would like
    it. The bundled dataset is synthetic and local; no external feed is
    contacted, and none is claimed to be.
    """
    provider = get_threat_intel_provider()
    stats = provider.stats()
    return {
        "provider": stats,
        "feeds": [
            {
                "name": "Local IOC database",
                "state": "ACTIVE",
                "detail": "Bundled dataset, queried on every analysis.",
                "indicators": stats.get("indicators_total", 0),
                "last_updated": stats.get("last_updated"),
            },
            {
                "name": "Trusted allowlist",
                "state": "ACTIVE",
                "detail": "Known-good domains. An allowlist entry is a "
                          "statement about reputation, so tunnelling or "
                          "behavioural evidence sets it aside.",
                "indicators": stats.get("trusted_domains", 0),
                "last_updated": stats.get("last_updated"),
            },
            {
                "name": "STIX/TAXII collection",
                "state": "NOT_CONNECTED",
                "detail": "No TAXII client exists in this build. The interface "
                          "it would implement is ThreatIntelProvider in "
                          "backend/app/intel/base.py - one class, plus one line "
                          "in get_threat_intel_provider().",
                "indicators": 0,
                "last_updated": None,
            },
            {
                "name": "Commercial feed",
                "state": "NOT_CONNECTED",
                "detail": "Deliberately out of scope for the prototype. Same "
                          "extension point as above.",
                "indicators": 0,
                "last_updated": None,
            },
        ],
        "honesty_note": "The bundled indicators are SYNTHETIC and use reserved "
                        "namespaces (.test/.invalid/.example). No real malicious "
                        "infrastructure is listed, and the platform never "
                        "resolves or contacts an indicator.",
    }


# -- protocol visibility -----------------------------------------------------


@router.get("/protocols", tags=["dns"])
async def protocols():
    """Which DNS transports this build actually serves."""
    gateway = get_gateway()
    status = gateway.status() if gateway is not None else {}
    tcp = (status.get("tcp") or {}) if status else {}
    settings = get_settings()
    return {
        "protocols": [
            {
                "name": "DNS over UDP",
                "short": "UDP",
                "state": "ACTIVE" if status.get("running") else "CONFIGURED",
                "port": settings.dns_listen_port,
                "detail": "Primary transport. Real wire-format DNS, parsed and "
                          "re-serialised with dnspython.",
            },
            {
                "name": "DNS over TCP",
                "short": "TCP",
                "state": "ACTIVE" if tcp.get("running") else "CONFIGURED",
                "port": settings.dns_listen_port,
                "detail": "Same port, 2-byte length-prefixed framing. Required "
                          "for truncated-response retries; identical policy to UDP.",
            },
            {
                "name": "DNS over TLS",
                "short": "DoT",
                "state": "NOT_IMPLEMENTED",
                "port": 853,
                "detail": "No TLS listener in this build. It would wrap the "
                          "existing TCP handler, which already frames DNS.",
            },
            {
                "name": "DNS over HTTPS",
                "short": "DoH",
                "state": "NOT_IMPLEMENTED",
                "port": 443,
                "detail": "No RFC 8484 endpoint in this build. It would reuse "
                          "the same handler behind an HTTP route.",
            },
        ],
        "note": "ACTIVE means a socket is bound right now. CONFIGURED means the "
                "transport is built and enabled but the gateway is not running. "
                "NOT_IMPLEMENTED means the code does not exist - it is not "
                "switched off, it is absent.",
    }
