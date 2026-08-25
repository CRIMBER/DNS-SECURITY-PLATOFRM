"""Domain-suspicion / DGA detection subsystem.

The application asks for ``get_dga_detector()`` and uses only the
``DGADetector`` interface. Swapping in a trained model is a change to this one
function - see ``set_dga_detector`` for the seam tests and future models use.
"""

from typing import Optional

from .base import DGADetector, DGAResult, dga_to_signal
from .behavioral import (
    BehavioralAnalyzer,
    BehavioralResult,
    HistoryBehavioralAnalyzer,
    behavioral_to_signal,
)
from .heuristic import BigramDGADetector
from .tunnel import (
    HeuristicTunnelDetector,
    TunnelDetector,
    TunnelResult,
    tunnel_to_signal,
)

__all__ = [
    "DGADetector",
    "DGAResult",
    "BigramDGADetector",
    "dga_to_signal",
    "get_dga_detector",
    "set_dga_detector",
    "TunnelDetector",
    "TunnelResult",
    "HeuristicTunnelDetector",
    "tunnel_to_signal",
    "get_tunnel_detector",
    "set_tunnel_detector",
    "BehavioralAnalyzer",
    "BehavioralResult",
    "HistoryBehavioralAnalyzer",
    "behavioral_to_signal",
    "get_behavioral_analyzer",
    "set_behavioral_analyzer",
]

_detector: Optional[DGADetector] = None


def get_dga_detector() -> DGADetector:
    """The active detector. Constructed once and reused.

    A trained classifier would be selected here, falling back to the
    statistical model when no model artefact is present.
    """
    global _detector
    if _detector is None:
        _detector = BigramDGADetector()
    return _detector


def set_dga_detector(detector: Optional[DGADetector]) -> None:
    """Override the active detector. Used by tests and future model loading."""
    global _detector
    _detector = detector


_tunnel: Optional[TunnelDetector] = None
_behavioral: Optional[BehavioralAnalyzer] = None


def get_tunnel_detector() -> TunnelDetector:
    """The active DNS-tunnelling detector."""
    global _tunnel
    if _tunnel is None:
        _tunnel = HeuristicTunnelDetector()
    return _tunnel


def set_tunnel_detector(detector: Optional[TunnelDetector]) -> None:
    global _tunnel
    _tunnel = detector


def get_behavioral_analyzer() -> BehavioralAnalyzer:
    """The active behavioural analyser."""
    global _behavioral
    if _behavioral is None:
        _behavioral = HistoryBehavioralAnalyzer()
    return _behavioral


def set_behavioral_analyzer(analyzer: Optional[BehavioralAnalyzer]) -> None:
    global _behavioral
    _behavioral = analyzer
