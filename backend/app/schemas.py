"""Pydantic models defining the public API contract.

The contract is deliberately declared in one place so that swapping the
heuristic DGA scorer for a trained model, or the local threat-intelligence
dataset for a live feed, changes no field the frontend depends on.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# -- requests ---------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """A single domain submitted for analysis."""

    domain: str = Field(
        ...,
        description="Domain to analyse. A full URL is accepted and the host is extracted.",
        json_schema_extra={"example": "suspicious-login-verify.top"},
    )
    source: str = Field(
        default="api",
        description="Where the request came from; recorded on the event for filtering.",
        max_length=32,
    )


class BulkAnalyzeRequest(BaseModel):
    """Several domains in one call. Used for demo seeding and batch testing."""

    domains: List[str] = Field(..., min_length=1, max_length=200)
    source: str = Field(default="bulk", max_length=32)


# -- error envelope ---------------------------------------------------------


class ErrorBody(BaseModel):
    code: str
    message: str
    detail: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorBody


# -- health -----------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    risk_config_version: str
    components: Dict[str, Any] = Field(
        description="Liveness of each pipeline component and what it is backed by."
    )


# -- analysis sub-objects ---------------------------------------------------


class RiskFactorModel(BaseModel):
    code: str
    label: str
    severity: str
    detail: str
    contribution: float = Field(
        description="Points this factor added to the final 0-100 risk score. "
        "Contributions sum to the final score."
    )


class SignalSummary(BaseModel):
    """Per-signal breakdown, so the fusion arithmetic is auditable."""

    name: str
    score: float = Field(description="This signal's own 0-100 suspicion score.")
    confidence: float = Field(
        description="0.0 means the signal had no information and was excluded "
        "from the weighted average - not that the domain is safe."
    )
    weight: float
    weighted_contribution: float
    used_in_fusion: bool


class ThreatIntelligenceModel(BaseModel):
    """Threat-intelligence result as returned to clients."""

    verdict: str = Field(
        description="MALICIOUS | SUSPICIOUS | TRUSTED | UNKNOWN. UNKNOWN means "
        "no dataset had information, which is not a statement of safety."
    )
    matched_indicator: Optional[str] = None
    match_type: Optional[str] = Field(
        default=None, description="'exact' or 'parent_domain'."
    )
    categories: List[str] = Field(default_factory=list)
    confidence: float
    source: str
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_updated: Optional[str] = None


class IntelLookupResponse(BaseModel):
    """Direct threat-intelligence lookup, with no other signals applied."""

    domain: str
    registrable_domain: str
    threat_intelligence: ThreatIntelligenceModel
    signal_score: float = Field(description="This signal's own 0-100 score.")
    signal_confidence: float = Field(
        description="0.0 means the lookup found nothing and the signal is "
        "excluded from risk fusion."
    )
    lookup_time_ms: float


class DGAAnalysisModel(BaseModel):
    """DGA / suspicion result as returned to clients."""

    score: float = Field(description="Suspicion value, 0.0-1.0.")
    model: str
    model_type: str = Field(
        description="PROTOTYPE_STATISTICAL for the bundled bigram model. This "
        "is a calibrated statistical score, not a trained classifier's "
        "posterior probability."
    )
    components: Dict[str, float] = Field(
        description="The measured inputs behind the score."
    )
    top_contributors: List[str] = Field(default_factory=list)
    confidence: float
    notes: Optional[str] = None


class DGAAnalysisResponse(BaseModel):
    """Direct DGA analysis, with no other signals applied."""

    domain: str
    registrable_domain: str
    analysed_label: str
    dga_analysis: DGAAnalysisModel
    signal_score: float
    signal_confidence: float
    analysis_time_ms: float


class FeatureInspectionResponse(BaseModel):
    """Debug view of stage 1+2 only: normalisation and lexical analysis.

    Exposed as a development/tuning aid; the dashboard does not use it.
    """

    input: str
    domain: str
    registrable_domain: str
    tld: str
    subdomain: str
    was_url: bool
    domain_features: Dict[str, Any]
    lexical_score: float
    lexical_confidence: float
    lexical_factors: List[RiskFactorModel]
    extraction_time_ms: float


# -- analysis ---------------------------------------------------------------


class AnalyzeResponse(BaseModel):
    """The full pipeline result: every signal, the fused score, the decision."""

    domain: str
    registrable_domain: str
    risk_score: int = Field(description="Fused risk, 0-100.")
    classification: str = Field(description="SAFE | SUSPICIOUS | MALICIOUS")
    decision: str = Field(description="ALLOW | MONITOR | BLOCK")
    confidence: float = Field(
        description="Evidence coverage: the share of total signal weight that "
        "actually reported. Low means few signals had information, not that "
        "the domain is safe."
    )
    threat_intelligence: ThreatIntelligenceModel
    dga_analysis: DGAAnalysisModel
    domain_features: Dict[str, Any]
    risk_factors: List[RiskFactorModel] = Field(
        description="Why the score is what it is. Contributions sum to risk_score."
    )
    signals: List[SignalSummary] = Field(
        description="Per-signal fusion accounting, so the arithmetic is auditable."
    )
    overrides_applied: List[str] = Field(default_factory=list)
    recommended_action: str
    analysis_time_ms: float
    stage_timings_ms: Dict[str, float]
    event_id: Optional[int] = None
    timestamp: str


class BulkAnalyzeResponse(BaseModel):
    analyzed: int
    failed: int
    results: List[AnalyzeResponse]
    errors: List[Dict[str, str]] = Field(default_factory=list)
    total_time_ms: float


# -- events and statistics --------------------------------------------------


class EventModel(BaseModel):
    id: int
    timestamp: str
    domain: str
    registrable_domain: str
    risk_score: int
    classification: str
    decision: str
    confidence: float
    threat_intelligence_verdict: str
    threat_categories: List[str] = Field(default_factory=list)
    matched_indicator: Optional[str] = None
    dga_score: float
    lexical_score: float
    analysis_time_ms: float
    top_factors: List[Dict[str, Any]] = Field(default_factory=list)
    overrides_applied: List[str] = Field(default_factory=list)
    source: str


class EventsResponse(BaseModel):
    events: List[EventModel]
    total: int
    limit: int
    offset: int


class StatsResponse(BaseModel):
    """Dashboard aggregates. Every value is computed from stored events."""

    total_analyzed: int
    allowed: int
    monitored: int
    blocked: int
    threats_detected: int = Field(
        description="Events classified SUSPICIOUS or MALICIOUS."
    )
    by_classification: Dict[str, int]
    by_decision: Dict[str, int]
    by_threat_intel_verdict: Dict[str, int]
    risk_distribution: List[Dict[str, Any]]
    threat_categories: Dict[str, int]
    top_risky_domains: List[Dict[str, Any]]
    activity: List[Dict[str, Any]]
    performance: Dict[str, Any]
