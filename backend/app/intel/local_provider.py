"""File-backed threat-intelligence provider.

Loads the bundled datasets into memory once at construction and answers
lookups with dictionary hits, so a lookup is O(number of labels) regardless of
dataset size.

Matching is **most-specific-wins**: candidate suffixes are generated from the
full domain down to the registrable domain, and the first one found in any
dataset decides the verdict. That is what allows a precise malicious indicator
(``compromised-host.example.com``) to override a broader allowlist entry
(``example.com``) - the real behaviour needed when a reputable domain hosts a
compromised subdomain.

Matching deliberately stops at the registrable domain, so a query can never
match on a public suffix alone (``.com``, ``.co.in``).
"""

from typing import Any, Dict, List, Optional

from ..config import load_json_data
from .base import IntelResult, IntelVerdict, MatchType, ThreatIntelProvider


class LocalFileThreatIntelProvider(ThreatIntelProvider):
    """Threat intelligence backed by the bundled JSON datasets."""

    name = "local_dataset"

    def __init__(
        self,
        indicators: Optional[Dict[str, Any]] = None,
        trusted: Optional[Dict[str, Any]] = None,
    ) -> None:
        indicator_data = (
            indicators
            if indicators is not None
            else load_json_data("intel", "data", "indicators.json")
        )
        trusted_data = (
            trusted
            if trusted is not None
            else load_json_data("intel", "data", "trusted.json")
        )

        self.source = indicator_data.get("source", "local_dataset_v1")
        self.last_updated = indicator_data.get("last_updated")
        self.trusted_source = trusted_data.get("source", "local_dataset_v1")

        self._indicators: Dict[str, Dict[str, Any]] = {}
        for entry in indicator_data.get("indicators", []):
            key = str(entry.get("indicator", "")).strip().lower().rstrip(".")
            if key:
                self._indicators[key] = entry

        self._trusted: Dict[str, str] = {}
        for domain in trusted_data.get("trusted_domains", []):
            key = str(domain).strip().lower().rstrip(".")
            if key:
                self._trusted[key] = self.trusted_source

    # -- matching -----------------------------------------------------------

    @staticmethod
    def _candidates(domain: str, registrable_domain: str) -> List[str]:
        """Suffixes to test, most specific first, stopping at the registrable
        domain so a public suffix can never match on its own."""
        domain = domain.rstrip(".")
        registrable = (registrable_domain or domain).rstrip(".")

        results: List[str] = []
        labels = domain.split(".")
        registrable_label_count = len(registrable.split("."))

        for index in range(0, len(labels) - registrable_label_count + 1):
            candidate = ".".join(labels[index:])
            if candidate and candidate not in results:
                results.append(candidate)

        if registrable and registrable not in results:
            results.append(registrable)
        return results

    def lookup(self, domain: str, registrable_domain: str) -> IntelResult:
        domain = (domain or "").strip().lower().rstrip(".")
        registrable_domain = (registrable_domain or domain).strip().lower().rstrip(".")

        for candidate in self._candidates(domain, registrable_domain):
            is_exact = candidate == domain

            entry = self._indicators.get(candidate)
            if entry is not None:
                verdict = IntelVerdict(entry.get("verdict", "MALICIOUS"))
                confidence = float(entry.get("confidence", 0.9))
                if not is_exact:
                    # A parent-domain hit is slightly weaker evidence about
                    # this specific host than a direct hit.
                    confidence *= 0.9
                return IntelResult(
                    verdict=verdict,
                    matched_indicator=candidate,
                    match_type=MatchType.EXACT if is_exact else MatchType.PARENT_DOMAIN,
                    categories=list(entry.get("categories", [])),
                    confidence=round(confidence, 3),
                    source=self.source,
                    description=entry.get("description"),
                    first_seen=entry.get("first_seen"),
                    last_updated=self.last_updated,
                )

            if candidate in self._trusted:
                return IntelResult(
                    verdict=IntelVerdict.TRUSTED,
                    matched_indicator=candidate,
                    match_type=MatchType.EXACT if is_exact else MatchType.PARENT_DOMAIN,
                    categories=["allowlisted"],
                    confidence=0.9 if is_exact else 0.85,
                    source=self._trusted[candidate],
                    description="Known-good domain on the trusted allowlist.",
                    last_updated=self.last_updated,
                )

        # No information. Reported with confidence 0.0 by the signal converter,
        # never as a low-risk score.
        return IntelResult(
            verdict=IntelVerdict.UNKNOWN,
            source=self.source,
            confidence=0.0,
            description="Not present in any configured threat-intelligence dataset.",
            last_updated=self.last_updated,
        )

    # -- introspection ------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        malicious = sum(
            1
            for e in self._indicators.values()
            if e.get("verdict") == IntelVerdict.MALICIOUS.value
        )
        suspicious = sum(
            1
            for e in self._indicators.values()
            if e.get("verdict") == IntelVerdict.SUSPICIOUS.value
        )
        categories: Dict[str, int] = {}
        for entry in self._indicators.values():
            for category in entry.get("categories", []):
                categories[category] = categories.get(category, 0) + 1

        return {
            "provider": self.name,
            "source": self.source,
            "last_updated": self.last_updated,
            "indicators_total": len(self._indicators),
            "malicious": malicious,
            "suspicious": suspicious,
            "trusted_domains": len(self._trusted),
            "categories": dict(sorted(categories.items())),
            "dataset_note": "Synthetic indicators in reserved namespaces only.",
        }
