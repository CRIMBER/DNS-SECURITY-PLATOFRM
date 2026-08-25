"""DNS tunnelling detection.

DNS tunnelling smuggles data through DNS by encoding it into query names. The
payload has to live in the labels, which leaves measurable traces:

* the subdomain carries far more characters than a human would ever type
* those characters are drawn from an encoding alphabet (hex, base32, base64ish)
  rather than from language
* entropy is near-maximal because the payload is compressed or encrypted
* label counts are unusual, because payloads are split across labels
* the record types skew to TXT / NULL / CNAME, which carry more return data
  than an A record

This detector measures the query *name*, plus the record type when the DNS
gateway supplies it. It is a per-query detector: it sees one name at a time.
Detecting the volumetric side of tunnelling - hundreds of unique subdomains
under one registrable domain - is the behavioural analyser's job, and the two
corroborate each other through the risk engine.

ASYMMETRIC CONFIDENCE, as everywhere else in this system: when this detector
finds nothing it reports confidence 0.0 and is excluded from fusion entirely.
"No tunnelling evidence" says nothing about whether a domain is phishing, so
this signal must never dilute another one.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import RiskConfig, get_risk_config
from ..core.classification import DELEGATED_SPAN, NameKind
from ..core.features import DomainFeatures, shannon_entropy
from ..core.signals import RiskFactor, Severity, Signal, clamp

SIGNAL_NAME = "tunnel"

# Kinds with no attacker-varied payload span. An address literal has no labels
# below it, and the labels of a reverse-DNS name encode an address rather than
# carrying data.
_NO_PAYLOAD_SPAN = frozenset({NameKind.IP_LITERAL, NameKind.INFRASTRUCTURE})

# Record types that return more data than an address, and so are favoured by
# tunnelling tools for the downstream channel.
HIGH_CAPACITY_TYPES = frozenset({"TXT", "NULL", "CNAME", "MX", "SRV", "ANY"})

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_BASE32_RE = re.compile(r"^[a-z2-7]+$")
_BASE64ISH_RE = re.compile(r"^[a-z0-9+/=_-]+$")
_VOWELS = frozenset("aeiou")


@dataclass
class TunnelResult:
    score: float = 0.0
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    measurements: Dict[str, Any] = field(default_factory=dict)
    method: str = "heuristic_tunnel_v1"
    method_type: str = "PROTOTYPE_HEURISTIC"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "indicators": self.indicators,
            "measurements": {
                k: (round(v, 4) if isinstance(v, float) else v)
                for k, v in self.measurements.items()
            },
            "method": self.method,
            "method_type": self.method_type,
        }


class TunnelDetector(ABC):
    """Any model that scores how much a query name looks like a covert channel."""

    name: str = "abstract"

    @abstractmethod
    def analyse(
        self, features: DomainFeatures, context: Optional[Dict[str, Any]] = None
    ) -> TunnelResult:
        """Score one query name, optionally using DNS context (record type)."""

    @abstractmethod
    def info(self) -> Dict[str, Any]:
        """Provenance for the health endpoint."""


def _encoding_alphabet(label: str) -> Optional[str]:
    """Name the encoding alphabet a label appears to be drawn from."""
    if len(label) < 8:
        return None
    if _HEX_RE.match(label):
        return "hex"
    if _BASE32_RE.match(label) and not any(c in _VOWELS for c in label[:12]):
        return "base32"
    if _BASE64ISH_RE.match(label):
        letters = [c for c in label if c.isalpha()]
        if letters:
            vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
            if vowel_ratio < 0.15:
                return "base64ish"
    return None


class HeuristicTunnelDetector(TunnelDetector):
    """Transparent, rule-based tunnelling detector.

    Labelled PROTOTYPE_HEURISTIC. It is not a trained classifier and claims no
    accuracy figure.
    """

    name = "heuristic_tunnel_v1"

    def analyse(
        self,
        features: DomainFeatures,
        context: Optional[Dict[str, Any]] = None,
        config: Optional[RiskConfig] = None,
    ) -> TunnelResult:
        cfg = config or get_risk_config()
        thresholds = cfg.get("tunnel.thresholds", {}) or {}
        points = cfg.get("tunnel.points", {}) or {}
        context = context or {}

        # SCOPE: the exfiltration channel is DELEGATED_SPAN - everything the
        # zone operator can vary from one query to the next.
        #
        # For a name with a zone owner this is the same span `features.subdomain`
        # already gave, and reading it here changes no score: an attacker who
        # owns evilsite.pages.dev and one who owns victimzone.test both get 86
        # for the same payload, because both own a zone and vary the labels
        # below it. Naming the span explicitly is the point - it stops the
        # next detector from re-deriving "the subdomain" for itself and getting
        # a different answer.
        #
        # What DOES change is the guard below: an address literal has no labels
        # to carry a payload, and a reverse-DNS name's labels encode an address
        # rather than data.
        classification = features.classification
        if classification is not None and classification.kind in _NO_PAYLOAD_SPAN:
            return TunnelResult(
                score=0.0,
                confidence=0.0,
                indicators=[],
                measurements={
                    "not_applicable": True,
                    "name_kind": classification.kind.value,
                    "query_type": (context or {}).get("query_type"),
                },
            )
        subdomain = (
            classification.scope(DELEGATED_SPAN)
            if classification is not None
            else features.subdomain
        ) or ""
        labels = [part for part in subdomain.split(".") if part]

        measurements: Dict[str, Any] = {
            "subdomain_length": len(subdomain),
            "subdomain_label_count": len(labels),
            "longest_label": max((len(part) for part in labels), default=0),
            "subdomain_entropy": round(shannon_entropy(subdomain.replace(".", "")), 3),
            "query_type": context.get("query_type"),
            "encoding_alphabet": None,
        }

        # No subdomain means no room to carry a payload. Report nothing, with
        # zero confidence, so the signal is dropped from fusion.
        if not labels:
            return TunnelResult(
                score=0.0,
                confidence=0.0,
                indicators=[],
                measurements=measurements,
            )

        total = 0.0
        indicators: List[str] = []

        def fire(name: str, amount: float) -> None:
            nonlocal total
            total += amount
            indicators.append(name)

        if len(subdomain) >= int(thresholds.get("subdomain_length", 40)):
            fire("long_subdomain", float(points.get("long_subdomain", 28)))

        if measurements["longest_label"] >= int(thresholds.get("label_length", 30)):
            fire("long_label", float(points.get("long_label", 24)))

        # Gated on length: entropy over a short subdomain is noisy, the same
        # way it was for short registrable labels in the DGA model. Without the
        # gate, ordinary names like selector1._domainkey trip this rule.
        if len(subdomain) >= int(thresholds.get("min_length_for_entropy", 30)) and (
            measurements["subdomain_entropy"] >= float(thresholds.get("entropy", 3.8))
        ):
            fire("high_subdomain_entropy", float(points.get("high_subdomain_entropy", 22)))

        if len(labels) >= int(thresholds.get("label_count", 5)):
            fire("many_labels", float(points.get("many_labels", 14)))

        alphabet = None
        for part in labels:
            alphabet = _encoding_alphabet(part)
            if alphabet:
                break
        if alphabet:
            measurements["encoding_alphabet"] = alphabet
            fire("encoded_payload", float(points.get("encoded_payload", 26)))

        query_type = (context.get("query_type") or "").upper()
        if query_type in HIGH_CAPACITY_TYPES and indicators:
            # Only meaningful alongside another indicator - TXT lookups are
            # perfectly ordinary on their own.
            fire("high_capacity_record", float(points.get("high_capacity_record", 12)))

        score = clamp(total)

        # Confidence rises with the number of independent indicators. One
        # indicator alone is weak; three together is a strong pattern.
        confidence_cfg = cfg.get("tunnel.confidence", {}) or {}
        if not indicators:
            confidence = 0.0
        elif len(indicators) == 1:
            confidence = float(confidence_cfg.get("single_indicator", 0.35))
        elif len(indicators) == 2:
            confidence = float(confidence_cfg.get("two_indicators", 0.6))
        else:
            confidence = float(confidence_cfg.get("multiple_indicators", 0.85))

        return TunnelResult(
            score=score,
            confidence=confidence,
            indicators=indicators,
            measurements=measurements,
        )

    def info(self) -> Dict[str, Any]:
        return {
            "model": self.name,
            "model_type": "PROTOTYPE_HEURISTIC",
            "accuracy_claimed": None,
            "note": "Transparent rule-based detector over query-name structure. "
                    "No labelled evaluation has been performed, so no accuracy "
                    "is reported.",
        }


def tunnel_to_signal(result: TunnelResult, config) -> Signal:
    """Convert a tunnelling result into the uniform ``Signal``."""
    factors: List[RiskFactor] = []

    if result.indicators:
        readable = {
            "long_subdomain": "an unusually long subdomain",
            "long_label": "an over-long single label",
            "high_subdomain_entropy": "near-random characters",
            "many_labels": "an unusual number of labels",
            "encoded_payload": "an encoded-looking payload",
            "high_capacity_record": "a high-capacity record type",
        }
        described = ", ".join(readable.get(i, i) for i in result.indicators)
        severity = Severity.HIGH if len(result.indicators) >= 3 else Severity.MEDIUM
        factors.append(
            RiskFactor(
                code="DNS_TUNNEL_INDICATORS",
                label="Possible DNS tunnelling ({} indicators)".format(
                    len(result.indicators)
                ),
                severity=severity,
                detail="The query name carries {}. Together these are consistent "
                "with data being encoded into DNS labels rather than a name "
                "someone chose. Subdomain is {} characters across {} labels with "
                "{:.2f} bits/char entropy.".format(
                    described,
                    result.measurements.get("subdomain_length", 0),
                    result.measurements.get("subdomain_label_count", 0),
                    result.measurements.get("subdomain_entropy", 0.0),
                ),
                raw_points=result.score,
            )
        )
    else:
        factors.append(
            RiskFactor(
                code="DNS_TUNNEL_NONE",
                label="No DNS tunnelling indicators",
                severity=Severity.INFO,
                detail="The query name shows no sign of carrying an encoded "
                "payload. This rules out tunnelling only - it is not evidence "
                "the domain is safe, so this signal reports zero confidence and "
                "is excluded from risk fusion.",
                raw_points=0.0,
            )
        )

    return Signal(
        scope_key=DELEGATED_SPAN,
        name=SIGNAL_NAME,
        score=result.score,
        confidence=result.confidence,
        factors=factors,
        metadata=result.to_dict(),
    )
