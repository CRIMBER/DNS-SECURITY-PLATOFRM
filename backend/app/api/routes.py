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

from fastapi import APIRouter, Query

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
        "protocol": "udp",
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
