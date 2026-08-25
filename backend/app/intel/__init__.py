"""Threat-intelligence subsystem.

The rest of the application asks for ``get_threat_intel_provider()`` and only
ever uses the ``ThreatIntelProvider`` interface. Swapping the bundled dataset
for a live feed or a STIX/TAXII collection is a change to this one function.
"""

from typing import Optional

from .base import (
    IntelResult,
    IntelVerdict,
    MatchType,
    ThreatIntelProvider,
    intel_to_signal,
)
from .local_provider import LocalFileThreatIntelProvider

__all__ = [
    "IntelResult",
    "IntelVerdict",
    "MatchType",
    "ThreatIntelProvider",
    "LocalFileThreatIntelProvider",
    "intel_to_signal",
    "get_threat_intel_provider",
    "set_threat_intel_provider",
]

_provider: Optional[ThreatIntelProvider] = None


def get_threat_intel_provider() -> ThreatIntelProvider:
    """The active provider. Constructed once and reused."""
    global _provider
    if _provider is None:
        _provider = LocalFileThreatIntelProvider()
    return _provider


def set_threat_intel_provider(provider: Optional[ThreatIntelProvider]) -> None:
    """Override the active provider. Used by tests; the seam a live feed uses."""
    global _provider
    _provider = provider
