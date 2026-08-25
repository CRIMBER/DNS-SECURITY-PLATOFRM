"""Shared vocabulary for every analyzer in the detection pipeline.

Every analyzer - threat intelligence, DGA detection, lexical analysis, and any
component added later (behavioural, tunnelling, PCAP) - returns exactly one
``Signal``. The risk engine fuses whatever signals it is handed and knows
nothing about how any of them were produced.

That is the whole extensibility mechanism: adding a new detector means writing
one class that returns a ``Signal`` and adding one weight to the config file.
No change to the risk engine, the API contract, or the dashboard.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    """Human-facing severity of a single contributing factor."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskFactor:
    """One human-readable reason the score is what it is.

    Factors are *emitted by the code that fires them*, not reconstructed after
    the fact. That guarantees the explanation shown to an analyst can never
    drift away from the arithmetic that produced the score.
    """

    code: str
    """Stable machine-readable identifier, e.g. ``ENTROPY_HIGH``."""

    label: str
    """Short human-readable summary shown in the UI."""

    severity: Severity

    detail: str
    """One sentence explaining what was measured and why it matters."""

    raw_points: float = 0.0
    """Points this factor contributed inside its own sub-scorer's 0-100 scale."""

    contribution: float = 0.0
    """Points this factor contributed to the *final* score. Populated by the
    risk engine once signal weights are known, so the values shown in the UI
    sum to the final risk score."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "severity": self.severity.value,
            "detail": self.detail,
            "contribution": round(self.contribution, 2),
        }


@dataclass
class Signal:
    """The uniform output of every analyzer."""

    name: str
    """Signal identifier; must match a key in ``weights`` in risk_config.json."""

    score: float
    """Suspicion contributed by this signal alone, normalised to 0-100."""

    confidence: float
    """How much this signal trusts its own score, 0.0-1.0.

    Crucially, ``0.0`` means *"I have no information"*, not *"this is safe"*.
    A signal reporting zero confidence is dropped from the weighted average
    entirely rather than dragging the score toward zero. This is what stops a
    threat-intelligence miss from being read as proof of safety.
    """

    factors: List[RiskFactor] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Signal-specific detail passed through to the API response."""

    @property
    def is_informative(self) -> bool:
        return self.confidence > 0.0


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Constrain ``value`` to the inclusive range [low, high]."""
    return max(low, min(high, value))
