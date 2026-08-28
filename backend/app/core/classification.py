"""What kind of name is this, and which span should each detector read?

THE PROBLEM THIS SOLVES
-----------------------
Until this stage existed, every detector independently assumed the label below
the public suffix was a registrant-chosen brand name. That assumption is true
for exactly one kind of name. Applied to the others it produced confident
nonsense: ``192.168.1.10`` scored 95/BLOCK because the octets were measured for
digit ratio and dictionary coverage; ``42.1.168.192.in-addr.arpa`` scored
61/MONITOR because ``in-addr`` was scored as a brand label; every punycode
domain scored ~95 because an English bigram model cannot read Cyrillic.

So the pipeline now runs:

    RAW INPUT -> NORMALIZE -> PARSE -> CLASSIFY -> SELECT SCOPE -> DETECTORS

and this module is the CLASSIFY and SELECT SCOPE stages. It answers two
questions once, authoritatively, so no detector has to guess:

    1. What kind of name is this?          -> NameKind
    2. Which span should you analyse?      -> scopes[...]

WHAT THIS IS NOT
----------------
It is not an allowlist. Classifying a name as PROVIDER_HOST grants it nothing:
no score cap, no trusted verdict, no detector disabled. It records where a name
sits so that a detector can tell whether its own assumptions apply. Threat
intelligence, behavioural, tunnelling and brand/keyword analysis are unaffected
by classification in every category.
"""

import ipaddress
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Optional, Set

from ..config import load_json_data

_DATA = load_json_data("core", "data", "public_suffixes.json")

REGISTRY_SUFFIXES = frozenset(_DATA["registry_suffixes"]["suffixes"])
PROVIDER_SUFFIXES = frozenset(_DATA["provider_suffixes"]["suffixes"])
MULTI_LABEL_SUFFIXES = REGISTRY_SUFFIXES | PROVIDER_SUFFIXES

_SPECIAL = _DATA["special_use_suffixes"]
UNREGISTERED_SUFFIXES = frozenset(_SPECIAL["unregistered"])
# .test/.invalid/.example are reserved, but the labels inside them are ordinary
# registrant-shaped names, so they are analysed as normal registry domains.
REGISTRANT_SHAPED_SUFFIXES = frozenset(_SPECIAL["registrant_shaped"])

_INFRA = _DATA["infrastructure_suffixes"]
INFRASTRUCTURE_SUFFIXES = frozenset(_INFRA["suffixes"])
REVERSE_ZONES: Dict[str, int] = dict(_INFRA["reverse_zones"])


class NameKind(Enum):
    """What kind of name this is. Exactly one value applies."""

    REGISTRY_DOMAIN = "REGISTRY_DOMAIN"
    """A label a registrant chose and paid for, under a public registry suffix."""

    PROVIDER_HOST = "PROVIDER_HOST"
    """A label allocated inside a hosting provider's own namespace."""

    INFRASTRUCTURE = "INFRASTRUCTURE"
    """A DNS operational zone - everything under .arpa, including reverse DNS."""

    LOCAL_NAME = "LOCAL_NAME"
    """Special-use zone holding names nobody registered (.local, .localhost)."""

    IP_LITERAL = "IP_LITERAL"
    """An address, not a name."""

    SINGLE_LABEL = "SINGLE_LABEL"
    """One label, no suffix, not special-use. e.g. a WPAD or search-domain lookup."""

    MALFORMED = "MALFORMED"
    """Failed validation. Reserved: normalize() raises before reaching here."""


class SuffixKind(Enum):
    """Which section of the suffix data matched."""

    NONE = "NONE"
    REGISTRY = "REGISTRY"
    PROVIDER = "PROVIDER"
    SPECIAL_USE = "SPECIAL_USE"
    ARPA = "ARPA"


# -- scope keys -------------------------------------------------------------
# Named spans of one name. Detectors declare which they consume; collapsing
# them into a single "the domain" is what produced the tunnelling defect.

FULL_NAME = "full_name"
REGISTRABLE_DOMAIN = "registrable_domain"
REGISTRANT_LABEL = "registrant_label"
"""The single label below the suffix - the one a human may have CHOSEN.
Empty when nobody chose it."""

DELEGATED_SPAN = "delegated_span"
"""Everything below the registrable domain: what a zone operator varies per
query, and therefore the exfiltration channel."""

CONTROLLED_SPAN = "controlled_span"
"""delegated_span + registrant_label - everything one party controls."""

SEMANTIC_TEXT = "semantic_text"
"""The text to read for MEANING. Unicode form for an IDN, so brand and keyword
matching see what a human sees rather than the punycode."""


# -- which spans contain which ----------------------------------------------
# CONTROLLED_SPAN is DELEGATED_SPAN plus the registrant label by construction,
# so a detector reading it has already seen every byte a detector reading
# either of those two saw. DELEGATED_SPAN and REGISTRANT_LABEL share no bytes
# with each other.
#
# The risk engine needs this to tell two observations from one observation
# reported twice. Comparing scope keys for equality cannot see it: on a
# provider host the tunnelling detector reads CONTROLLED_SPAN while the DGA
# model reads REGISTRANT_LABEL - different keys over overlapping bytes, which
# is how a corroboration bonus came to be paid for an echo.
#
# Only the keys detectors actually declare appear here; the rest are read but
# never used as evidence identity.
_SCOPE_CONTAINS = {
    CONTROLLED_SPAN: frozenset({DELEGATED_SPAN, REGISTRANT_LABEL}),
}


def scope_contains(outer: str, inner: str) -> bool:
    """Whether reading ``outer`` already covers every byte of ``inner``."""
    if not outer or not inner:
        return False
    if outer == inner:
        return True
    return inner in _SCOPE_CONTAINS.get(outer, frozenset())


def independent_scopes(keys: Iterable[str]) -> Set[str]:
    """The keys not already covered by another key in the same set.

    ``{controlled_span, registrant_label}`` is one body of evidence rather
    than two - the second lies inside the first. ``{delegated_span,
    registrant_label}`` is genuinely two, because they share no bytes.

    Keys naming no span (a signal reading a database or a query history) are
    contained by nothing and contain nothing, so each counts for itself.
    """
    present = {key for key in keys if key}
    return {
        key
        for key in present
        if not any(
            other != key and scope_contains(other, key) for other in present
        )
    }


@dataclass(frozen=True)
class NameClassification:
    """The authoritative answer to 'what is this name, and what do I read?'"""

    kind: NameKind
    suffix_kind: SuffixKind = SuffixKind.NONE
    public_suffix: str = ""
    scopes: Dict[str, str] = field(default_factory=dict)

    scope_is_registrant_chosen: bool = False
    """Whether the label under analysis was chosen by a registrant. False for
    provider, infrastructure, local and IP names. This is the single fact a
    name-shape model needs in order to know its training distribution applies."""

    unicode_form: Optional[str] = None
    """Decoded IDN, when it differs from the ASCII form."""

    scripts: FrozenSet[str] = frozenset()
    """Unicode scripts present, so a model can distinguish 'out of my
    distribution' from 'random'."""

    is_reverse_dns: bool = False
    reverse_target: Optional[str] = None
    ip_address: Optional[str] = None
    ip_version: Optional[int] = None
    ip_is_private: Optional[bool] = None
    special_use: Optional[str] = None
    reason: str = ""
    """Why this classification was chosen. Surfaced so a verdict is auditable
    to its scope, not only to its score."""

    def scope(self, key: str) -> str:
        """The span for ``key``, or '' when this name has no such span."""
        return self.scopes.get(key, "")

    def has_scope(self, key: str) -> bool:
        """Whether ``key`` names a non-empty span. Empty means abstain."""
        return bool(self.scopes.get(key))

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind.value,
            "suffix_kind": self.suffix_kind.value,
            "public_suffix": self.public_suffix,
            "scopes": dict(self.scopes),
            "scope_is_registrant_chosen": self.scope_is_registrant_chosen,
            "unicode_form": self.unicode_form,
            "scripts": sorted(self.scripts),
            "is_reverse_dns": self.is_reverse_dns,
            "reverse_target": self.reverse_target,
            "ip_address": self.ip_address,
            "ip_version": self.ip_version,
            "ip_is_private": self.ip_is_private,
            "special_use": self.special_use,
            "reason": self.reason,
        }


# -- helpers ----------------------------------------------------------------


def public_suffix_of(labels: List[str]) -> str:
    """Longest matching multi-label suffix, else the final label."""
    for size in (3, 2):
        if len(labels) >= size + 1 or (len(labels) == size and size == 2):
            candidate = ".".join(labels[-size:])
            if candidate in MULTI_LABEL_SUFFIXES:
                return candidate
    return labels[-1] if labels else ""


def _scripts_of(text: str) -> FrozenSet[str]:
    """Unicode scripts present in ``text``, approximated by character name.

    unicodedata carries no script property, but the character name's first
    word is the script for every alphabet we care about ('CYRILLIC SMALL
    LETTER A'). Digits, hyphens and punctuation are ignored so they do not
    dilute the answer.
    """
    found = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        found.add(name.split()[0].title())
    return frozenset(found)


def _decode_idn(host: str) -> Optional[str]:
    """Unicode form of a punycode host, or None if it does not decode."""
    out = []
    changed = False
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                out.append(decoded)
                changed = changed or decoded != label
                continue
            except (UnicodeError, UnicodeDecodeError):
                return None
        out.append(label)
    return ".".join(out) if changed else None


def _reverse_target(labels: List[str], zone: str, version: int) -> Optional[str]:
    """Decode the address a PTR name encodes, or None if it is not well formed."""
    zone_labels = zone.split(".")
    body = labels[: -len(zone_labels)]
    if not body:
        return None
    try:
        if version == 4:
            if len(body) != 4:
                return None
            return str(ipaddress.IPv4Address(".".join(reversed(body))))
        if len(body) != 32:
            return None
        nibbles = "".join(reversed(body))
        packed = ":".join(nibbles[i:i + 4] for i in range(0, 32, 4))
        return str(ipaddress.IPv6Address(packed))
    except (ipaddress.AddressValueError, ValueError):
        return None


# -- classification ---------------------------------------------------------


def classify_ip_literal(host: str) -> NameClassification:
    """An address. No span is analysable as text."""
    address = ipaddress.ip_address(host)
    return NameClassification(
        kind=NameKind.IP_LITERAL,
        suffix_kind=SuffixKind.NONE,
        scopes={FULL_NAME: str(address)},
        scope_is_registrant_chosen=False,
        ip_address=str(address),
        ip_version=address.version,
        ip_is_private=bool(
            address.is_private or address.is_loopback or address.is_link_local
        ),
        reason=(
            "IPv{} address literal, not a name. There is no label to analyse, "
            "so textual name-shape analysis does not apply.".format(address.version)
        ),
    )


def classify(
    host: str,
    labels: List[str],
    is_punycode: bool = False,
) -> NameClassification:
    """Classify a validated host and select the span each detector reads."""
    unicode_form = _decode_idn(host) if is_punycode else None

    # -- single label -------------------------------------------------------
    if len(labels) == 1:
        label = labels[0]
        if label in UNREGISTERED_SUFFIXES:
            return NameClassification(
                kind=NameKind.LOCAL_NAME,
                suffix_kind=SuffixKind.SPECIAL_USE,
                public_suffix=label,
                scopes={FULL_NAME: host},
                special_use=label,
                reason="Special-use name reserved by RFC; never registered.",
            )
        # A real query with real risk (wpad, search-domain lookups). It keeps a
        # label to analyse - the model simply has less to work with, which is a
        # confidence question rather than a reason to abstain.
        return NameClassification(
            kind=NameKind.SINGLE_LABEL,
            suffix_kind=SuffixKind.NONE,
            scopes={
                FULL_NAME: host,
                REGISTRANT_LABEL: label,
                CONTROLLED_SPAN: label,
                SEMANTIC_TEXT: unicode_form or label,
            },
            scope_is_registrant_chosen=True,
            unicode_form=unicode_form,
            scripts=_scripts_of(unicode_form or label),
            reason=(
                "Single label with no public suffix. Analysed, but one label "
                "carries less evidence than a registrable domain."
            ),
        )

    suffix = public_suffix_of(labels)
    suffix_labels = suffix.split(".")
    tail = labels[-1]

    # -- infrastructure (.arpa) --------------------------------------------
    if tail in INFRASTRUCTURE_SUFFIXES:
        zone_name = ".".join(labels[-2:]) if len(labels) >= 2 else tail
        version = REVERSE_ZONES.get(zone_name)
        target = (
            _reverse_target(labels, zone_name, version) if version else None
        )
        return NameClassification(
            kind=NameKind.INFRASTRUCTURE,
            suffix_kind=SuffixKind.ARPA,
            public_suffix=zone_name if version else tail,
            # No registrant label and no analysable payload span: the labels
            # encode an address or a delegation, they are not chosen text.
            scopes={FULL_NAME: host, REGISTRABLE_DOMAIN: zone_name},
            scope_is_registrant_chosen=False,
            is_reverse_dns=bool(version),
            reverse_target=target,
            reason=(
                "Reverse-DNS name under {}; its labels encode an address."
                .format(zone_name)
                if version
                else "DNS infrastructure zone under .arpa; labels are "
                     "operator-defined, not registrant-chosen."
            ),
        )

    # -- special use --------------------------------------------------------
    if tail in UNREGISTERED_SUFFIXES:
        # Device and host names nobody registered. The name still carries
        # meaning worth a brand check (hp-laserjet.local), but there is no
        # registrant label, so registrant-label analysis is meaningless.
        return NameClassification(
            kind=NameKind.LOCAL_NAME,
            suffix_kind=SuffixKind.SPECIAL_USE,
            public_suffix=tail,
            scopes={
                FULL_NAME: host,
                REGISTRABLE_DOMAIN: ".".join(labels[-2:]),
                DELEGATED_SPAN: ".".join(labels[:-2]),
                SEMANTIC_TEXT: (unicode_form or host).rsplit("." + tail, 1)[0],
            },
            scope_is_registrant_chosen=False,
            special_use=tail,
            unicode_form=unicode_form,
            scripts=_scripts_of(
                (unicode_form or host).rsplit("." + tail, 1)[0]),
            reason=(
                "Special-use zone .{}: names here are device or host names "
                "that nobody registered.".format(tail)
            ),
        )

    # -- registry / provider ------------------------------------------------
    if suffix in PROVIDER_SUFFIXES:
        suffix_kind = SuffixKind.PROVIDER
        kind = NameKind.PROVIDER_HOST
        registrant_chosen = False
        reason = (
            "Label allocated inside the {} namespace rather than chosen and "
            "registered by the operator of this host. Recorded only - no "
            "detector is disabled and no score is capped.".format(suffix)
        )
    else:
        suffix_kind = SuffixKind.SPECIAL_USE if (
            suffix in REGISTRANT_SHAPED_SUFFIXES
        ) else SuffixKind.REGISTRY
        kind = NameKind.REGISTRY_DOMAIN
        registrant_chosen = True
        reason = (
            "Registrant-chosen label under the {} suffix.".format(suffix)
            if suffix_kind is SuffixKind.REGISTRY
            else "Reserved suffix .{}, but labels here are ordinary "
                 "registrant-shaped names and are analysed as such.".format(suffix)
        )

    registrable_labels = labels[-(len(suffix_labels) + 1):]
    registrable = ".".join(registrable_labels)
    registrant_label = registrable_labels[0]
    delegated = ".".join(labels[: -(len(suffix_labels) + 1)])
    controlled = ".".join(filter(None, [delegated, registrant_label]))

    semantic = controlled
    if unicode_form:
        u_labels = unicode_form.split(".")
        semantic = ".".join(u_labels[: -len(suffix_labels)]) or controlled

    return NameClassification(
        kind=kind,
        suffix_kind=suffix_kind,
        public_suffix=suffix,
        scopes={
            FULL_NAME: host,
            REGISTRABLE_DOMAIN: registrable,
            REGISTRANT_LABEL: registrant_label,
            DELEGATED_SPAN: delegated,
            CONTROLLED_SPAN: controlled,
            SEMANTIC_TEXT: semantic,
        },
        scope_is_registrant_chosen=registrant_chosen,
        unicode_form=unicode_form,
        # Measured on the span actually analysed, NOT the whole host: an ASCII
        # public suffix would otherwise add "Latin" to every IDN and make each
        # one look mixed-script.
        scripts=_scripts_of(semantic),
        special_use=suffix if suffix_kind is SuffixKind.SPECIAL_USE else None,
        reason=reason,
    )
