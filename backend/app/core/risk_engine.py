"""Risk engine: fuses independent signals into one explained decision.

Fusion is a **confidence-weighted average**:

    base = Σ(weight_i × confidence_i × score_i) / Σ(weight_i × confidence_i)

The denominator is the key detail. A signal reporting ``confidence = 0.0``
drops out of *both* sums, so it neither raises nor lowers the score. That is
what makes a threat-intelligence miss an absence of evidence rather than a vote
for safety - an unlisted domain is judged purely on the signals that did have
something to say.

After fusion, a small set of explicit policy overrides may apply. Each one that
fires records itself as a visible risk factor carrying the exact number of
points it moved the score, so the factor list always sums to the final score.
The explanation is the computation, not a story told about it afterwards.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import RiskConfig, get_risk_config
from .signals import RiskFactor, Severity, Signal, clamp


@dataclass
class SignalSummary:
    """How one signal fed into the final score. Makes the maths auditable."""

    name: str
    score: float
    confidence: float
    weight: float
    weighted_contribution: float
    used_in_fusion: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "weight": self.weight,
            "weighted_contribution": round(self.weighted_contribution, 2),
            "used_in_fusion": self.used_in_fusion,
        }


@dataclass
class RiskAssessment:
    """The engine's verdict, with everything needed to justify it."""

    score: int
    raw_score: float
    classification: str
    decision: str
    confidence: float
    evidence_coverage: float
    factors: List[RiskFactor] = field(default_factory=list)
    signals: List[SignalSummary] = field(default_factory=list)
    overrides_applied: List[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.score,
            "classification": self.classification,
            "decision": self.decision,
            "confidence": round(self.confidence, 3),
            "evidence_coverage": round(self.evidence_coverage, 3),
            "risk_factors": [f.to_dict() for f in self.factors],
            "signals": [s.to_dict() for s in self.signals],
            "overrides_applied": self.overrides_applied,
            "recommended_action": self.recommended_action,
        }


class RiskEngine:
    """Combines signals into a 0-100 score and a decision."""

    def __init__(self, config: Optional[RiskConfig] = None) -> None:
        self.config = config or get_risk_config()

    # -- fusion -------------------------------------------------------------

    def _fuse(self, signals: List[Signal]):
        """Confidence-weighted average, plus per-signal accounting."""
        weights = self.config.weights
        summaries: List[SignalSummary] = []

        divisor = 0.0
        numerator = 0.0
        for signal in signals:
            weight = float(weights.get(signal.name, 0.0))
            effective = weight * signal.confidence
            divisor += effective
            numerator += effective * signal.score

        base = (numerator / divisor) if divisor > 0 else 0.0

        for signal in signals:
            weight = float(weights.get(signal.name, 0.0))
            effective = weight * signal.confidence
            # Points this signal contributed to the fused base score.
            contribution = (effective / divisor) * signal.score if divisor > 0 else 0.0
            summaries.append(
                SignalSummary(
                    name=signal.name,
                    score=signal.score,
                    confidence=signal.confidence,
                    weight=weight,
                    weighted_contribution=contribution,
                    used_in_fusion=effective > 0,
                )
            )

        total_weight = sum(float(w) for w in weights.values()) or 1.0
        coverage = divisor / total_weight
        return base, summaries, divisor, coverage

    @staticmethod
    def _distribute(signal: Signal, contribution: float) -> None:
        """Split a signal's contribution across its own factors.

        Each factor receives a share proportional to the points it raised
        inside its sub-scorer, so the numbers shown to an analyst add up to the
        final score exactly.
        """
        total_points = sum(max(0.0, f.raw_points) for f in signal.factors)
        if total_points <= 0:
            # Purely informational factors (e.g. "no anomalies"): nothing to
            # attribute, and the contribution is zero anyway.
            for factor in signal.factors:
                factor.contribution = 0.0
            return
        for factor in signal.factors:
            share = max(0.0, factor.raw_points) / total_points
            factor.contribution = contribution * share

    # -- overrides ----------------------------------------------------------

    def _apply_overrides(
        self, score: float, signals: List[Signal]
    ) -> "tuple":
        """Apply policy rules after fusion.

        Returns ``(score, override_factors, names)``. Floors run before
        bonuses; the trusted ceiling runs last so an allowlist entry is
        authoritative.
        """
        by_name = {s.name: s for s in signals}
        factor_codes = {f.code for s in signals for f in s.factors}
        applied: List[str] = []
        override_factors: List[RiskFactor] = []

        def move(new_score: float, code: str, label: str,
                 severity: Severity, detail: str, name: str) -> float:
            delta = new_score - score
            if abs(delta) < 0.01:
                return score
            override_factors.append(
                RiskFactor(
                    code=code,
                    label=label,
                    severity=severity,
                    detail=detail,
                    raw_points=delta,
                    contribution=delta,
                )
            )
            applied.append(name)
            return new_score

        # 1. Confirmed threat intelligence sets a floor.
        rule = self.config.override("ti_malicious_floor")
        ti = by_name.get("threat_intel")
        if rule.get("enabled", True) and ti is not None:
            verdict = ti.metadata.get("verdict")
            if (
                verdict == "MALICIOUS"
                and ti.confidence >= float(rule.get("min_confidence", 0.9))
                and score < float(rule.get("floor", 85))
            ):
                floor = float(rule.get("floor", 85))
                score = move(
                    floor,
                    "OVERRIDE_TI_FLOOR",
                    "Threat-intelligence floor applied",
                    Severity.CRITICAL,
                    "A high-confidence threat-intelligence match raises the "
                    "score to at least {:.0f}. This is a floor, not a "
                    "short-circuit - other signals can still push it "
                    "higher.".format(floor),
                    "ti_malicious_floor",
                )

        # 2. Brand impersonation is strong standalone evidence.
        rule = self.config.override("brand_impersonation_floor")
        if (
            rule.get("enabled", True)
            and "BRAND_IMPERSONATION" in factor_codes
            and score < float(rule.get("floor", 60))
        ):
            floor = float(rule.get("floor", 60))
            score = move(
                floor,
                "OVERRIDE_BRAND_FLOOR",
                "Brand-impersonation floor applied",
                Severity.HIGH,
                "The domain borrows a well-known brand name it does not own. "
                "Typosquatting is weak on lexical points alone but strong "
                "evidence in its own right, so a floor of {:.0f} "
                "applies.".format(floor),
                "brand_impersonation_floor",
            )

        # 3. Independent signals agreeing is itself evidence.
        rule = self.config.override("corroboration_bonus")
        if rule.get("enabled", True):
            threshold = float(rule.get("signal_score_threshold", 70))
            high_signals = [
                s for s in signals if s.is_informative and s.score >= threshold
            ]
            if len(high_signals) >= int(rule.get("min_signals", 2)):
                bonus = float(rule.get("bonus", 8))
                score = move(
                    clamp(score + bonus),
                    "OVERRIDE_CORROBORATION",
                    "Multiple independent signals agree",
                    Severity.HIGH,
                    "{} independent signals ({}) each scored at or above "
                    "{:.0f}. Agreement between unrelated detection methods is "
                    "itself evidence.".format(
                        len(high_signals),
                        ", ".join(s.name for s in high_signals),
                        threshold,
                    ),
                    "corroboration_bonus",
                )

        # 4. A high DGA score on an abuse-heavy TLD.
        rule = self.config.override("suspicious_tld_dga_bonus")
        dga = by_name.get("dga")
        if (
            rule.get("enabled", True)
            and "SUSPICIOUS_TLD" in factor_codes
            and dga is not None
            and dga.score / 100.0 >= float(rule.get("dga_threshold", 0.8))
        ):
            bonus = float(rule.get("bonus", 5))
            score = move(
                clamp(score + bonus),
                "OVERRIDE_TLD_DGA",
                "DGA-like name on an abuse-heavy TLD",
                Severity.MEDIUM,
                "A randomised name registered under a TLD with a high abuse "
                "rate is a well-documented combination.",
                "suspicious_tld_dga_bonus",
            )

        # 5. Allowlist ceiling, applied last so it is authoritative.
        rule = self.config.override("ti_trusted_ceiling")
        if rule.get("enabled", True) and ti is not None:
            if ti.metadata.get("verdict") == "TRUSTED":
                ceiling = float(rule.get("ceiling", 25))
                if score > ceiling:
                    score = move(
                        ceiling,
                        "OVERRIDE_TRUSTED_CEILING",
                        "Trusted-allowlist ceiling applied",
                        Severity.INFO,
                        "This domain is on the trusted allowlist, so its score "
                        "is capped at {:.0f}. This prevents false positives on "
                        "legitimate domains with an unusual lexical "
                        "shape.".format(ceiling),
                        "ti_trusted_ceiling",
                    )

        return score, override_factors, applied

    # -- recommendation -----------------------------------------------------

    def _recommend(self, decision: str, signals: List[Signal]) -> str:
        by_name = {s.name: s for s in signals}
        ti = by_name.get("threat_intel")
        dga = by_name.get("dga")
        verdict = ti.metadata.get("verdict") if ti else "UNKNOWN"

        if decision == "BLOCK":
            if verdict == "MALICIOUS":
                return (
                    "Block resolution. Confirmed threat-intelligence match - "
                    "quarantine any host that queried this domain and check for "
                    "further indicators from the same campaign."
                )
            return (
                "Block resolution and raise an alert. No threat-intelligence "
                "match exists, so this domain is a candidate for submission as "
                "a new indicator."
            )
        if decision == "MONITOR":
            if dga is not None and dga.score >= 50:
                return (
                    "Allow but log and monitor. The name shows algorithmic "
                    "characteristics; correlate with query volume and timing "
                    "before escalating."
                )
            return (
                "Allow but log and monitor. Evidence is mixed - review if this "
                "domain reappears or is queried by multiple hosts."
            )
        if verdict == "TRUSTED":
            return "Allow. Domain is on the trusted allowlist."
        return "Allow. No signal reported meaningful risk."

    # -- entry point --------------------------------------------------------

    def assess(self, signals: List[Signal]) -> RiskAssessment:
        base, summaries, divisor, coverage = self._fuse(signals)

        for signal, summary in zip(signals, summaries):
            self._distribute(signal, summary.weighted_contribution)

        score, override_factors, applied = self._apply_overrides(base, signals)
        score = clamp(score)

        factors: List[RiskFactor] = []
        for signal in signals:
            factors.extend(signal.factors)
        factors.extend(override_factors)
        # Most impactful first, informational last.
        factors.sort(key=lambda f: -f.contribution)

        band = self.config.classify(score)
        decision = band["decision"]

        if divisor <= 0:
            # No signal had anything to say. Say so rather than reporting a
            # confident zero.
            factors.append(
                RiskFactor(
                    code="NO_EVIDENCE",
                    label="No signal produced usable evidence",
                    severity=Severity.INFO,
                    detail="Every signal reported zero confidence, so no score "
                    "could be computed from evidence.",
                )
            )

        return RiskAssessment(
            score=int(round(score)),
            raw_score=score,
            classification=band["classification"],
            decision=decision,
            confidence=coverage,
            evidence_coverage=coverage,
            factors=factors,
            signals=summaries,
            overrides_applied=applied,
            recommended_action=self._recommend(decision, signals),
        )
