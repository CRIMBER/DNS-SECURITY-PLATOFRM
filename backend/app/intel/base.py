"""Threat-intelligence provider interface.

The pipeline depends only on this interface, never on where the data came
from. Replacing the bundled local dataset with a live feed, a STIX/TAXII
collection, or a commercial API means writing one new subclass and changing
which provider is constructed - no change to the risk engine, the API contract,
or the dashboard.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..core.signals import RiskFactor, Severity, Signal

SIGNAL_NAME = "threat_intel"


class IntelVerdict(str, Enum):
    """What threat intelligence knows about a domain."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    TRUSTED = "TRUSTED"
    UNKNOWN = "UNKNOWN"
    """Not present in any dataset.

    This means *no information*, NOT 'safe'. It is reported with confidence
    0.0 so the risk engine excludes it from the weighted average rather than
    letting an empty lookup drag the score toward zero.
    """


class MatchType(str, Enum):
    EXACT = "exact"
    PARENT_DOMAIN = "parent_domain"


@dataclass
class IntelResult:
    """The outcome of one threat-intelligence lookup."""

    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    matched_indicator: Optional[str] = None
    match_type: Optional[MatchType] = None
    categories: List[str] = field(default_factory=list)
    confidence: float = 0.0
    source: str = "none"
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "matched_indicator": self.matched_indicator,
            "match_type": self.match_type.value if self.match_type else None,
            "categories": self.categories,
            "confidence": round(self.confidence, 3),
            "source": self.source,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_updated": self.last_updated,
        }


class ThreatIntelProvider(ABC):
    """Any source of domain reputation."""

    name: str = "abstract"

    @abstractmethod
    def lookup(self, domain: str, registrable_domain: str) -> IntelResult:
        """Return what this source knows about the domain.

        Implementations must return ``IntelVerdict.UNKNOWN`` with
        ``confidence = 0.0`` when they have no information - never a
        low-risk score, which would be an unsupported claim of safety.
        """

    @abstractmethod
    def stats(self) -> Dict[str, Any]:
        """Dataset size and freshness, for the health endpoint."""


def intel_to_signal(result: IntelResult, config) -> Signal:
    """Convert a lookup result into the uniform ``Signal`` the engine consumes.

    Verdict scores are configuration, not code, so the policy can be retuned in
    ``config/risk_config.json``.
    """
    scores = config.get("threat_intel.verdict_scores", {}) or {}
    score = float(scores.get(result.verdict.value, 0.0))

    factors: List[RiskFactor] = []
    confidence = result.confidence

    if result.verdict == IntelVerdict.MALICIOUS:
        factors.append(
            RiskFactor(
                code="TI_MALICIOUS",
                label="Threat-intelligence match: known malicious",
                severity=Severity.CRITICAL,
                detail="Matched indicator '{}' ({} match) in {}. "
                "Categories: {}. Reported confidence {:.0%}.".format(
                    result.matched_indicator,
                    result.match_type.value if result.match_type else "direct",
                    result.source,
                    ", ".join(result.categories) or "unclassified",
                    result.confidence,
                ),
                raw_points=score,
            )
        )
    elif result.verdict == IntelVerdict.SUSPICIOUS:
        factors.append(
            RiskFactor(
                code="TI_SUSPICIOUS",
                label="Threat-intelligence match: suspicious",
                severity=Severity.HIGH,
                detail="Matched '{}' in {}. Categories: {}.".format(
                    result.matched_indicator,
                    result.source,
                    ", ".join(result.categories) or "unclassified",
                ),
                raw_points=score,
            )
        )
    elif result.verdict == IntelVerdict.TRUSTED:
        factors.append(
            RiskFactor(
                code="TI_TRUSTED",
                label="On the trusted allowlist",
                severity=Severity.INFO,
                detail="'{}' is a known-good domain in {}.".format(
                    result.matched_indicator, result.source
                ),
                raw_points=0.0,
            )
        )
    else:
        # The important case. No match is an absence of evidence.
        factors.append(
            RiskFactor(
                code="TI_NO_MATCH",
                label="No threat-intelligence match",
                severity=Severity.INFO,
                detail="This domain appears in no threat-intelligence dataset. "
                "That is an absence of evidence, not evidence of safety - the "
                "verdict is therefore decided by the other signals.",
                raw_points=0.0,
            )
        )
        confidence = float(
            config.get("unknown_domain_policy.unknown_confidence", 0.0)
        )

    return Signal(
        name=SIGNAL_NAME,
        score=score,
        confidence=confidence,
        factors=factors,
        metadata=result.to_dict(),
    )
