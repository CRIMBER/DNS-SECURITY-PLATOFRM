"""Analysis pipeline: the single path a domain takes through the system.

Orchestrates normalisation, feature extraction, every registered signal
provider, risk fusion and event persistence, measuring each stage with
``perf_counter`` so reported timings are real rather than asserted.

Adding a new detector means appending one entry to ``_collect_signals`` and one
weight in ``config/risk_config.json``. Nothing else in the system changes.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import RiskConfig, get_risk_config
from ..detection import dga_to_signal, get_dga_detector
from ..intel import get_threat_intel_provider, intel_to_signal
from .features import DomainFeatures, extract_features
from .lexical import score_lexical
from .normalizer import NormalizedDomain, normalize
from .risk_engine import RiskAssessment, RiskEngine
from .signals import Signal


@dataclass
class AnalysisResult:
    """Everything one analysis produced."""

    normalized: NormalizedDomain
    features: DomainFeatures
    signals: List[Signal]
    assessment: RiskAssessment
    timings_ms: Dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0
    event_id: Optional[int] = None

    def signal_named(self, name: str) -> Optional[Signal]:
        for signal in self.signals:
            if signal.name == name:
                return signal
        return None

    @property
    def intel_metadata(self) -> Dict[str, Any]:
        signal = self.signal_named("threat_intel")
        return signal.metadata if signal else {}

    @property
    def dga_metadata(self) -> Dict[str, Any]:
        signal = self.signal_named("dga")
        return signal.metadata if signal else {}


class AnalysisPipeline:
    """Runs a domain through every stage of analysis."""

    def __init__(self, config: Optional[RiskConfig] = None) -> None:
        self.config = config or get_risk_config()
        self.engine = RiskEngine(self.config)

    def _collect_signals(self, features: DomainFeatures, timings: Dict[str, float]):
        """Run every registered signal provider.

        This list is the extension point. A behavioural analyzer, a DNS
        tunnelling detector or a PCAP-derived signal is added here and given a
        weight in the config; the risk engine needs no knowledge of it.
        """
        signals: List[Signal] = []

        started = time.perf_counter()
        provider = get_threat_intel_provider()
        intel_result = provider.lookup(
            features.domain, features.registrable_domain
        )
        signals.append(intel_to_signal(intel_result, self.config))
        timings["threat_intel"] = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        detector = get_dga_detector()
        dga_result = detector.analyse(features)
        signals.append(dga_to_signal(dga_result, self.config))
        timings["dga"] = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        signals.append(score_lexical(features, self.config))
        timings["lexical"] = (time.perf_counter() - started) * 1000.0

        return signals

    def analyse(self, raw_domain: str) -> AnalysisResult:
        """Full pipeline. Raises ``DomainValidationError`` on bad input."""
        total_started = time.perf_counter()
        timings: Dict[str, float] = {}

        started = time.perf_counter()
        normalized = normalize(raw_domain)
        timings["normalize"] = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        features = extract_features(normalized)
        timings["features"] = (time.perf_counter() - started) * 1000.0

        signals = self._collect_signals(features, timings)

        started = time.perf_counter()
        assessment = self.engine.assess(signals)
        timings["risk_engine"] = (time.perf_counter() - started) * 1000.0

        total_ms = (time.perf_counter() - total_started) * 1000.0

        return AnalysisResult(
            normalized=normalized,
            features=features,
            signals=signals,
            assessment=assessment,
            timings_ms={k: round(v, 3) for k, v in timings.items()},
            total_ms=round(total_ms, 3),
        )


_pipeline: Optional[AnalysisPipeline] = None


def get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline


def reset_pipeline() -> None:
    """Drop the cached pipeline so a reloaded config takes effect."""
    global _pipeline
    _pipeline = None
