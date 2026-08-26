"""DGA / domain-suspicion detector interface.

The pipeline depends only on ``DGADetector``. Replacing the bundled
statistical model with a trained classifier means writing one subclass and
changing which detector ``get_dga_detector()`` constructs - the API contract,
the risk engine and the dashboard are untouched.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..core.features import DomainFeatures
from ..core.classification import REGISTRANT_LABEL
from ..core.signals import RiskFactor, Severity, Signal

SIGNAL_NAME = "dga"


@dataclass
class DGAResult:
    """Output of a domain-suspicion analysis."""

    score: float = 0.0
    """Suspicion value in 0.0-1.0.

    This is a calibrated statistical score, NOT the output probability of a
    trained discriminative classifier. ``model_type`` states which it is, and
    the API surfaces that field verbatim so no consumer can mistake one for
    the other.
    """

    model: str = "unknown"
    model_type: str = "PROTOTYPE_STATISTICAL"
    components: Dict[str, float] = field(default_factory=dict)
    """The measured inputs behind the score, for explainability."""

    top_contributors: List[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "model": self.model,
            "model_type": self.model_type,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "top_contributors": self.top_contributors,
            "confidence": round(self.confidence, 3),
            "notes": self.notes,
        }


class DGADetector(ABC):
    """Any model that scores how algorithmically-generated a domain looks."""

    name: str = "abstract"
    model_type: str = "ABSTRACT"

    @abstractmethod
    def analyse(self, features: DomainFeatures) -> DGAResult:
        """Score the domain's registrable label."""

    @abstractmethod
    def info(self) -> Dict[str, Any]:
        """Model provenance, for the health endpoint."""


def dga_to_signal(result: DGAResult, config) -> Signal:
    """Convert a DGA result into the uniform ``Signal`` the risk engine uses."""
    score_100 = result.score * 100.0

    thresholds = config.get("dga.factor_thresholds", {}) or {}
    high = float(thresholds.get("high", 0.80))
    moderate = float(thresholds.get("moderate", 0.50))

    contributors = ", ".join(result.top_contributors) if result.top_contributors else "none"
    llr_detail = (
        "Character-transition plausibility sits {:.1f} standard deviations below "
        "the mean of legitimate domains.".format(result.components.get("z_score", 0.0))
    )

    factors: List[RiskFactor] = []
    if result.score >= high:
        factors.append(
            RiskFactor(
                code="DGA_HIGH",
                label="Strong DGA characteristics (suspicion {:.2f})".format(result.score),
                severity=Severity.HIGH,
                detail="{} Main contributors: {}.".format(llr_detail, contributors),
                raw_points=score_100,
            )
        )
    elif result.score >= moderate:
        factors.append(
            RiskFactor(
                code="DGA_MODERATE",
                label="Moderate DGA characteristics (suspicion {:.2f})".format(result.score),
                severity=Severity.MEDIUM,
                detail="{} Main contributors: {}.".format(llr_detail, contributors),
                raw_points=score_100,
            )
        )
    elif not result.components:
        # The detector declined to measure at all. Saying "the character
        # transitions are consistent with human-registered names" here would
        # be a claim about a measurement that never happened - and it appeared
        # verbatim under an IP address, which has no label to have transitions.
        factors.append(
            RiskFactor(
                code="DGA_NOT_APPLICABLE",
                label="DGA analysis does not apply to this name",
                severity=Severity.INFO,
                detail=result.notes or "This detector reported no measurement.",
                raw_points=score_100,
            )
        )
    else:
        factors.append(
            RiskFactor(
                code="DGA_LOW",
                label="No significant DGA characteristics (suspicion {:.2f})".format(
                    result.score
                ),
                severity=Severity.INFO,
                detail="The label's character transitions are consistent with "
                "human-registered domain names. Note this rules out algorithmic "
                "generation only - it is not evidence the domain is safe, so "
                "this signal abstains from the weighted average entirely.",
                raw_points=score_100,
            )
        )

    return Signal(
        # Same span as the lexical shape rules - see Signal.scope_key.
        scope_key=REGISTRANT_LABEL,
        name=SIGNAL_NAME,
        score=score_100,
        confidence=result.confidence,
        factors=factors,
        metadata=result.to_dict(),
    )
