"""Lexical feature extraction.

Turns a normalised domain into ~25 measurable properties. These are *facts
about the string* - nothing here decides anything. Scoring happens in
``lexical.py``, DGA probability in ``detection/``, and the verdict in
``risk_engine.py``.

Importantly: none of these features proves maliciousness. A long domain with
many digits is not automatically bad. They are inputs to a probabilistic
suspicion signal, and the risk engine treats them as such.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import load_json_data, load_wordlist
from .classification import SEMANTIC_TEXT, NameClassification, NameKind
from .normalizer import NormalizedDomain

VOWELS = frozenset("aeiou")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_TLD_DATA = load_json_data("core", "data", "suspicious_tlds.json")
SUSPICIOUS_TLD_WEIGHTS: Dict[str, float] = _TLD_DATA.get("weights", {})

_KEYWORD_DATA = load_json_data("core", "data", "suspicious_keywords.json")
SUSPICIOUS_KEYWORD_WEIGHTS: Dict[str, float] = _KEYWORD_DATA.get("weights", {})
SUSPICIOUS_KEYWORDS: List[str] = sorted(SUSPICIOUS_KEYWORD_WEIGHTS)

_BRAND_DATA = load_json_data("core", "data", "brands.json")
# brand token -> every registrable domain that brand legitimately operates.
BRANDS: Dict[str, List[str]] = {
    brand: list(domains)
    for brand, domains in _BRAND_DATA.get("brands", {}).items()
}
_MIN_BRAND_LENGTH = 5

DICTIONARY = load_wordlist("core", "data", "words.txt")
_MIN_DICT_WORD = 3
_MAX_DICT_WORD = 14
# Inflected forms are recognised by stripping a suffix rather than by listing
# every form in the wordlist: "banking" resolves via "bank", "services" via
# "service". Keeps the wordlist small without losing recall.
_SUFFIXES = ("ing", "ers", "ed", "es", "er", "ly", "s")


def _is_word(chunk: str) -> bool:
    """True if ``chunk`` is a dictionary word or a simple inflection of one."""
    if chunk in DICTIONARY:
        return True
    for suffix in _SUFFIXES:
        if len(chunk) - len(suffix) >= _MIN_DICT_WORD and chunk.endswith(suffix):
            stem = chunk[: -len(suffix)]
            if stem in DICTIONARY:
                return True
            # "banking" -> "bank", but also "running" -> "run" (doubled
            # consonant) and "storing" -> "store" (dropped 'e').
            if len(stem) > _MIN_DICT_WORD and stem[-1] == stem[-2] and stem[:-1] in DICTIONARY:
                return True
            if stem + "e" in DICTIONARY:
                return True
    return False


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character.

    Random-looking strings spread their characters evenly and score high;
    real words reuse a small set of letters and score lower.
    """
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def max_run(text: str, predicate) -> int:
    """Longest consecutive run of characters satisfying ``predicate``."""
    best = current = 0
    for ch in text:
        if predicate(ch):
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def max_repeat_run(text: str) -> int:
    """Longest run of the *same* character, e.g. ``aaaa`` -> 4."""
    best = current = 1
    for i in range(1, len(text)):
        current = current + 1 if text[i] == text[i - 1] else 1
        best = max(best, current)
    return best if text else 0


def levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Edit distance with early exit; returns ``max_distance + 1`` if exceeded."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (ca != cb),
                )
            )
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def dictionary_coverage(text: str) -> float:
    """Fraction of characters explainable as real dictionary words.

    ``onlinebanking`` -> high coverage. ``kq3v9z7jx1p8w`` -> zero. This is one
    of the strongest and most explainable separators between human-registered
    domains and algorithmically generated ones.
    """
    if not text:
        return 0.0
    letters = re.sub(r"[^a-z]", "", text)
    if len(letters) < _MIN_DICT_WORD:
        return 0.0

    covered = [False] * len(letters)
    i = 0
    while i < len(letters):
        longest = 0
        upper = min(_MAX_DICT_WORD, len(letters) - i)
        for size in range(upper, _MIN_DICT_WORD - 1, -1):
            if _is_word(letters[i : i + size]):
                longest = size
                break
        if longest:
            for k in range(i, i + longest):
                covered[k] = True
            i += longest
        else:
            i += 1
    return sum(covered) / len(letters)


@dataclass
class DomainFeatures:
    """Measurable lexical properties of a domain. Pure description, no verdict."""

    domain: str
    registrable_domain: str
    sld: str
    tld: str
    subdomain: str

    length: int = 0
    sld_length: int = 0
    label_count: int = 0
    subdomain_count: int = 0
    max_label_length: int = 0
    mean_label_length: float = 0.0

    digit_count: int = 0
    digit_ratio: float = 0.0
    hyphen_count: int = 0
    hyphen_ratio: float = 0.0
    vowel_ratio: float = 0.0
    consonant_ratio: float = 0.0
    unique_char_ratio: float = 0.0
    max_consonant_run: int = 0
    max_digit_run: int = 0
    max_repeat_run: int = 0

    entropy: float = 0.0
    sld_entropy: float = 0.0
    normalized_entropy: float = 0.0
    char_class_distribution: Dict[str, float] = field(default_factory=dict)

    tld_is_suspicious: bool = False
    tld_risk_weight: float = 0.0
    dictionary_word_coverage: float = 0.0

    is_ip_literal: bool = False
    is_punycode: bool = False
    has_underscore: bool = False
    is_single_label: bool = False

    suspicious_keywords: List[str] = field(default_factory=list)
    keyword_max_weight: float = 0.0
    brand_impersonation: bool = False
    brand_substring_only: bool = False
    brand_target: Optional[str] = None
    brand_match_type: Optional[str] = None

    classification: Optional[NameClassification] = None
    """What kind of name this is, and the span each detector should read.

    Carried through from the normalizer. Before this existed the classifier's
    answer stopped at this boundary and every detector re-derived domain
    semantics from ``sld``/``subdomain``, each making the same wrong
    assumption: that the label below the public suffix is always a
    registrant-chosen brand name.
    """

    def scope(self, key: str) -> str:
        """The span ``key`` names, or '' when this name has no such span.

        Detectors call this instead of reaching for ``sld`` or ``subdomain``
        directly. An empty span means the detector should abstain - it is not
        a zero-length name to score.
        """
        if self.classification is None:
            return ""
        return self.classification.scope(key)

    @property
    def name_kind(self) -> Optional[NameKind]:
        return self.classification.kind if self.classification else None

    def to_dict(self) -> Dict[str, Any]:
        """API-facing view: rounded floats, no internal-only fields."""
        return {
            "length": self.length,
            "sld_length": self.sld_length,
            "label_count": self.label_count,
            "subdomain_count": self.subdomain_count,
            "max_label_length": self.max_label_length,
            "digit_count": self.digit_count,
            "digit_ratio": round(self.digit_ratio, 3),
            "hyphen_count": self.hyphen_count,
            "vowel_ratio": round(self.vowel_ratio, 3),
            "unique_char_ratio": round(self.unique_char_ratio, 3),
            "max_consonant_run": self.max_consonant_run,
            "max_digit_run": self.max_digit_run,
            "entropy": round(self.entropy, 3),
            "sld_entropy": round(self.sld_entropy, 3),
            "normalized_entropy": round(self.normalized_entropy, 3),
            "char_class_distribution": {
                k: round(v, 3) for k, v in self.char_class_distribution.items()
            },
            "tld": self.tld,
            "tld_is_suspicious": self.tld_is_suspicious,
            "tld_risk_weight": round(self.tld_risk_weight, 2),
            "dictionary_word_coverage": round(self.dictionary_word_coverage, 3),
            "is_punycode": self.is_punycode,
            "is_ip_literal": self.is_ip_literal,
            "suspicious_keywords": self.suspicious_keywords,
            "brand_impersonation": self.brand_impersonation,
            "brand_target": self.brand_target,
            "name_classification": (
                self.classification.to_dict() if self.classification else None
            ),
        }


def _detect_brand_impersonation(nd: NormalizedDomain) -> Dict[str, Any]:
    """Flag domains borrowing a well-known brand name they do not own.

    Three cases, in decreasing confidence:
      1. the brand appears as a whole token  (``paypal-secure.xyz``)
      2. the registrable label is one or two edits away (``paypa1``, ``gooogle``)
      3. the brand appears only as a substring (``mypaypalhelp.com``)

    A domain the brand actually operates is never flagged, which is why each
    brand maps to a list of legitimate domains rather than a single one.
    """
    result: Dict[str, Any] = {
        "impersonation": False,
        "substring_only": False,
        "target": None,
        "match_type": None,
    }
    if nd.is_ip_literal:
        return result

    analysed = nd.domain
    if nd.public_suffix and analysed.endswith("." + nd.public_suffix):
        analysed = analysed[: -(len(nd.public_suffix) + 1)]
    tokens = set(t for t in _TOKEN_SPLIT_RE.split(analysed) if t)

    def owned_by(brand_domains: List[str]) -> bool:
        return nd.registrable_domain in brand_domains

    for brand, legitimate_domains in BRANDS.items():
        if len(brand) < _MIN_BRAND_LENGTH or owned_by(legitimate_domains):
            continue

        if brand in tokens:
            result.update(
                impersonation=True,
                target=legitimate_domains[0],
                match_type="token",
            )
            return result

        if nd.sld != brand and levenshtein(nd.sld, brand, max_distance=2) <= 2:
            result.update(
                impersonation=True,
                target=legitimate_domains[0],
                match_type="typosquat",
            )
            return result

    # Weaker substring match, only if nothing stronger fired.
    for brand, legitimate_domains in BRANDS.items():
        if len(brand) < _MIN_BRAND_LENGTH or owned_by(legitimate_domains):
            continue
        if brand in analysed:
            result.update(
                substring_only=True,
                target=legitimate_domains[0],
                match_type="substring",
            )
            return result

    return result


def extract_features(nd: NormalizedDomain) -> DomainFeatures:
    """Compute the full lexical feature set for a normalised domain."""
    stripped = nd.domain.replace(".", "")
    sld = nd.sld
    label_lengths = [len(label) for label in nd.labels] or [0]

    digit_count = sum(ch.isdigit() for ch in stripped)
    hyphen_count = stripped.count("-")
    alpha_chars = [ch for ch in stripped if ch.isalpha()]
    vowel_count = sum(ch in VOWELS for ch in alpha_chars)
    total = len(stripped) or 1

    entropy = shannon_entropy(stripped)
    tld_weight = SUSPICIOUS_TLD_WEIGHTS.get(nd.tld, 0.0)
    classified = len(alpha_chars) + digit_count + hyphen_count
    other_ratio = max(0.0, 1.0 - classified / total)

    # Keywords are matched against SEMANTIC_TEXT: the part of the name below
    # its public suffix, in the form a human reads. Subdomains are covered
    # (`secure-login.evil.test`), a suffix like `gov.in` can never itself
    # trigger a hit, and an internationalised name is matched on its decoded
    # Unicode rather than on `xn--...`, which never matches anything.
    keyword_scope = ""
    if nd.classification is not None:
        keyword_scope = nd.classification.scope(SEMANTIC_TEXT)
    if not keyword_scope:
        keyword_scope = nd.domain
        if nd.public_suffix and keyword_scope.endswith("." + nd.public_suffix):
            keyword_scope = keyword_scope[: -(len(nd.public_suffix) + 1)]
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in keyword_scope]
    # Drop keywords fully contained in a longer match, e.g. keep "signin" only.
    found_keywords = [
        kw
        for kw in found_keywords
        if not any(kw != other and kw in other for other in found_keywords)
    ]
    keyword_max_weight = max(
        [SUSPICIOUS_KEYWORD_WEIGHTS.get(kw, 0.0) for kw in found_keywords] or [0.0]
    )

    brand = _detect_brand_impersonation(nd)

    return DomainFeatures(
        classification=nd.classification,
        domain=nd.domain,
        registrable_domain=nd.registrable_domain,
        sld=sld,
        tld=nd.tld,
        subdomain=nd.subdomain,
        length=len(nd.domain),
        sld_length=len(sld),
        label_count=len(nd.labels),
        subdomain_count=len(nd.subdomain.split(".")) if nd.subdomain else 0,
        max_label_length=max(label_lengths),
        mean_label_length=sum(label_lengths) / len(label_lengths),
        digit_count=digit_count,
        digit_ratio=digit_count / total,
        hyphen_count=hyphen_count,
        hyphen_ratio=hyphen_count / total,
        vowel_ratio=(vowel_count / len(alpha_chars)) if alpha_chars else 0.0,
        consonant_ratio=(
            (len(alpha_chars) - vowel_count) / len(alpha_chars) if alpha_chars else 0.0
        ),
        unique_char_ratio=len(set(stripped)) / total,
        max_consonant_run=max_run(
            stripped, lambda c: c.isalpha() and c not in VOWELS
        ),
        max_digit_run=max_run(stripped, lambda c: c.isdigit()),
        max_repeat_run=max_repeat_run(stripped),
        entropy=entropy,
        sld_entropy=shannon_entropy(sld),
        normalized_entropy=(entropy / math.log2(total)) if total > 1 else 0.0,
        char_class_distribution={
            "alpha": len(alpha_chars) / total,
            "digit": digit_count / total,
            "hyphen": hyphen_count / total,
            "other": other_ratio,
        },
        tld_is_suspicious=tld_weight > 0.0,
        tld_risk_weight=tld_weight,
        dictionary_word_coverage=dictionary_coverage(sld),
        is_ip_literal=nd.is_ip_literal,
        is_punycode=nd.is_punycode,
        has_underscore=nd.has_underscore,
        is_single_label=nd.is_single_label,
        suspicious_keywords=found_keywords,
        keyword_max_weight=keyword_max_weight,
        brand_impersonation=brand["impersonation"],
        brand_substring_only=brand["substring_only"],
        brand_target=brand["target"],
        brand_match_type=brand["match_type"],
    )
