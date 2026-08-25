"""Domain-suspicion / DGA detection subsystem.

The application asks for ``get_dga_detector()`` and uses only the
``DGADetector`` interface. Swapping in a trained model is a change to this one
function - see ``set_dga_detector`` for the seam tests and future models use.
"""

from typing import Optional

from .base import DGADetector, DGAResult, dga_to_signal
from .heuristic import BigramDGADetector

__all__ = [
    "DGADetector",
    "DGAResult",
    "BigramDGADetector",
    "dga_to_signal",
    "get_dga_detector",
    "set_dga_detector",
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
