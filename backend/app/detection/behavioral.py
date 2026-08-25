"""Behavioural analysis over observed query history.

Every other signal in this system judges a domain in isolation, from the name
alone. This one asks a different question: **how has this domain behaved?**

It reads the event store - the same table the dashboard reads - and looks for
patterns that only appear over time:

* **Beaconing / burst querying.** Malware polling a C2 endpoint produces a
  regular, high-rate stream of queries that a person browsing does not.
* **Subdomain fan-out.** Many distinct subdomains under one registrable domain
  is the volumetric signature of DNS tunnelling, and of C2 that encodes a
  session id into the name. Corroborates the per-query tunnel detector.
* **NXDOMAIN ratio.** A DGA works by trying many generated names until one
  resolves, so the failures pile up under the same infrastructure.
* **Escalating risk.** The same registrable domain repeatedly scoring high
  across different names is itself evidence.

ASYMMETRIC CONFIDENCE. A domain seen once has no behaviour to analyse, so this
signal reports confidence 0.0 and is dropped from fusion. It can only ever add
risk once evidence accumulates - it never argues that a domain is safe.

This is the component that makes the extensibility claim concrete: it was added
by writing one class returning a ``Signal`` and adding one weight to the config.
The risk engine, the API contract and the dashboard were not touched.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..config import RiskConfig, get_risk_config
from ..core.features import DomainFeatures
from ..core.signals import RiskFactor, Severity, Signal, clamp

SIGNAL_NAME = "behavioral"


@dataclass
class BehavioralResult:
    score: float = 0.0
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    observations: Dict[str, Any] = field(default_factory=dict)
    method: str = "history_heuristic_v1"
    method_type: str = "PROTOTYPE_HEURISTIC"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "indicators": self.indicators,
            "observations": self.observations,
            "method": self.method,
            "method_type": self.method_type,
        }


class BehavioralAnalyzer(ABC):
    """Any model that scores a domain from its observed query history."""

    name: str = "abstract"

    @abstractmethod
    def analyse(self, features: DomainFeatures) -> BehavioralResult:
        """Score the registrable domain from what has been seen before."""

    @abstractmethod
    def info(self) -> Dict[str, Any]:
        """Provenance for the health endpoint."""


class HistoryBehavioralAnalyzer(BehavioralAnalyzer):
    """Reads recent history for the registrable domain from the event store."""

    name = "history_heuristic_v1"

    def __init__(self, repository=None) -> None:
        self._repository = repository

    @property
    def repository(self):
        # Resolved on every access rather than memoised. The analyser is a
        # process-wide singleton, so caching the repository on first use meant
        # a later set_event_repository() was silently ignored and this analyser
        # kept reading a database nothing was writing to any more - it would
        # report "no history" forever, with no error to notice.
        #
        # An explicitly injected repository still wins, which is the seam tests
        # and future callers use.
        if self._repository is not None:
            return self._repository

        from ..storage.events import get_event_repository

        return get_event_repository()

    def analyse(
        self, features: DomainFeatures, config: Optional[RiskConfig] = None
    ) -> BehavioralResult:
        cfg = config or get_risk_config()
        thresholds = cfg.get("behavioral.thresholds", {}) or {}
        points = cfg.get("behavioral.points", {}) or {}
        window_minutes = int(cfg.get("behavioral.window_minutes", 60))

        try:
            history = self.repository.domain_history(
                features.registrable_domain, window_minutes=window_minutes
            )
        except Exception:
            # History is an enhancement, never a dependency. If the store is
            # unavailable the analyser abstains rather than failing the query.
            return BehavioralResult(
                score=0.0,
                confidence=0.0,
                observations={"history_available": False},
            )

        seen = history["total_queries"]
        observations: Dict[str, Any] = {
            "history_available": True,
            "window_minutes": window_minutes,
            "queries_in_window": seen,
            "distinct_subdomains": history["distinct_names"],
            "nxdomain_responses": history["nxdomain_count"],
            "blocked_before": history["blocked_count"],
            "max_risk_seen": history["max_risk_score"],
        }

        min_history = int(thresholds.get("min_queries_for_evidence", 3))
        if seen < min_history:
            # Nothing to say yet, and we say so rather than guessing.
            return BehavioralResult(
                score=0.0,
                confidence=0.0,
                indicators=[],
                observations=observations,
            )

        total = 0.0
        indicators: List[str] = []

        def fire(name: str, amount: float) -> None:
            nonlocal total
            total += amount
            indicators.append(name)

        rate_threshold = int(thresholds.get("burst_queries", 20))
        if seen >= rate_threshold:
            fire("query_burst", float(points.get("query_burst", 26)))

        fanout_threshold = int(thresholds.get("distinct_subdomains", 8))
        if history["distinct_names"] >= fanout_threshold:
            fire("subdomain_fanout", float(points.get("subdomain_fanout", 30)))

        nx_ratio = history["nxdomain_count"] / seen if seen else 0.0
        observations["nxdomain_ratio"] = round(nx_ratio, 3)
        if (
            seen >= int(thresholds.get("min_queries_for_nxdomain_ratio", 5))
            and nx_ratio >= float(thresholds.get("nxdomain_ratio", 0.5))
        ):
            fire("high_nxdomain_ratio", float(points.get("high_nxdomain_ratio", 22)))

        if history["blocked_count"] >= int(thresholds.get("prior_blocks", 3)):
            fire("repeatedly_blocked", float(points.get("repeatedly_blocked", 20)))

        score = clamp(total)

        confidence_cfg = cfg.get("behavioral.confidence", {}) or {}
        if not indicators:
            confidence = 0.0
        else:
            # More history means more trustworthy behavioural evidence.
            base = float(confidence_cfg.get("base", 0.5))
            per_query = float(confidence_cfg.get("per_query", 0.01))
            ceiling = float(confidence_cfg.get("max", 0.85))
            confidence = min(ceiling, base + per_query * seen)

        return BehavioralResult(
            score=score,
            confidence=confidence,
            indicators=indicators,
            observations=observations,
        )

    def info(self) -> Dict[str, Any]:
        return {
            "model": self.name,
            "model_type": "PROTOTYPE_HEURISTIC",
            "accuracy_claimed": None,
            "note": "Rule-based analysis over stored query history. Reports zero "
                    "confidence until enough history exists to say anything.",
        }


def behavioral_to_signal(result: BehavioralResult, config) -> Signal:
    """Convert a behavioural result into the uniform ``Signal``."""
    factors: List[RiskFactor] = []
    observations = result.observations

    if result.indicators:
        readable = {
            "query_burst": "an unusually high query rate",
            "subdomain_fanout": "many distinct subdomains",
            "high_nxdomain_ratio": "a high proportion of failed lookups",
            "repeatedly_blocked": "repeated prior blocks",
        }
        described = ", ".join(readable.get(i, i) for i in result.indicators)
        factors.append(
            RiskFactor(
                code="BEHAVIORAL_ANOMALY",
                label="Anomalous query behaviour ({} indicators)".format(
                    len(result.indicators)
                ),
                severity=Severity.HIGH if len(result.indicators) >= 2 else Severity.MEDIUM,
                detail="Over the last {} minutes this registrable domain shows "
                "{}: {} queries across {} distinct names, {} of which failed to "
                "resolve.".format(
                    observations.get("window_minutes", "?"),
                    described,
                    observations.get("queries_in_window", 0),
                    observations.get("distinct_subdomains", 0),
                    observations.get("nxdomain_responses", 0),
                ),
                raw_points=result.score,
            )
        )
    elif observations.get("history_available") and observations.get("queries_in_window"):
        factors.append(
            RiskFactor(
                code="BEHAVIORAL_NORMAL",
                label="No behavioural anomalies",
                severity=Severity.INFO,
                detail="{} prior queries in the window show no burst, fan-out or "
                "elevated failure rate. This rules out those patterns only - it "
                "is not evidence of safety, so the signal is excluded from "
                "fusion.".format(observations.get("queries_in_window", 0)),
                raw_points=0.0,
            )
        )
    else:
        factors.append(
            RiskFactor(
                code="BEHAVIORAL_NO_HISTORY",
                label="No behavioural history yet",
                severity=Severity.INFO,
                detail="This domain has not been seen often enough to analyse "
                "its behaviour. The signal abstains rather than guessing.",
                raw_points=0.0,
            )
        )

    return Signal(
        name=SIGNAL_NAME,
        score=result.score,
        confidence=result.confidence,
        factors=factors,
        metadata=result.to_dict(),
    )
