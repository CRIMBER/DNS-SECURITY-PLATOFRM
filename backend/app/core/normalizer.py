"""Input validation and canonicalisation.

This is the first stage of the pipeline and the only one that rejects input.
It exists so that no downstream analyzer ever has to defend itself against
malformed data, and so a judge typing something unexpected into the dashboard
gets a clear message instead of a stack trace.

It is deliberately permissive about *shape* (a pasted URL, a trailing dot, an
upper-case host, an internationalised name are all accepted and canonicalised)
and strict about *validity* (over-length labels, illegal characters, and
structurally impossible names are rejected).
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

from ..config import load_json_data

# RFC 1035 limits.
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
# Guard against absurd input before we do any work on it.
MAX_RAW_INPUT_LENGTH = 2048

_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")
_ALL_NUMERIC_RE = re.compile(r"^[0-9]+$")

_SUFFIX_DATA = load_json_data("core", "data", "public_suffixes.json")
MULTI_LABEL_SUFFIXES = frozenset(_SUFFIX_DATA.get("multi_label_suffixes", []))


class DomainValidationError(ValueError):
    """Raised for input that cannot be analysed as a domain name."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class NormalizedDomain:
    """A validated, canonical domain plus the structure the analyzers need."""

    original_input: str
    domain: str
    """Canonical form: lower-case, ASCII/punycode, no trailing dot, no port."""

    labels: List[str] = field(default_factory=list)
    tld: str = ""
    registrable_domain: str = ""
    """The domain one label below the public suffix, e.g. ``example.co.uk``."""

    sld: str = ""
    """The registrable label itself, e.g. ``example``. This is the label a DGA
    actually generates, so it carries most of the lexical signal."""

    subdomain: str = ""
    public_suffix: str = ""
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_single_label: bool = False
    has_underscore: bool = False
    was_url: bool = False
    """True if the operator pasted a full URL and we extracted the host."""


def _extract_host(raw: str) -> "tuple":
    """Pull a bare host out of whatever the user pasted.

    Returns ``(host, was_url)``.
    """
    text = raw.strip().strip("\"'<>").strip()
    was_url = False

    if "://" in text:
        parsed = urlsplit(text)
        host = parsed.hostname or ""
        was_url = True
        if not host:
            raise DomainValidationError(
                "INVALID_URL", "Could not extract a host name from that URL."
            )
        return host, was_url

    # A bare "example.com/path?q=1" or "example.com:8080" style input.
    if "/" in text or "?" in text or "#" in text:
        text = re.split(r"[/?#]", text, maxsplit=1)[0]
        was_url = True

    if "@" in text:  # strip user-info
        text = text.rsplit("@", 1)[1]

    # Strip a port, but leave bracketed IPv6 literals alone.
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            return text[1:end], was_url
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]

    return text, was_url


def _to_ascii(host: str) -> "tuple":
    """Convert an internationalised name to punycode.

    Returns ``(ascii_host, is_punycode)``.
    """
    if all(ord(ch) < 128 for ch in host):
        return host, any(label.startswith("xn--") for label in host.split("."))

    encoded_labels = []
    for label in host.split("."):
        if all(ord(ch) < 128 for ch in label):
            encoded_labels.append(label)
            continue
        try:
            encoded_labels.append(label.encode("idna").decode("ascii"))
        except (UnicodeError, UnicodeDecodeError):
            raise DomainValidationError(
                "IDN_ENCODING_FAILED",
                "That internationalised domain name could not be encoded to punycode.",
            )
    return ".".join(encoded_labels), True


def _public_suffix(labels: List[str]) -> str:
    """Longest matching public suffix, falling back to the final label."""
    if len(labels) >= 3:
        candidate = ".".join(labels[-3:])
        if candidate in MULTI_LABEL_SUFFIXES:
            return candidate
    if len(labels) >= 2:
        candidate = ".".join(labels[-2:])
        if candidate in MULTI_LABEL_SUFFIXES:
            return candidate
    return labels[-1]


def normalize(raw: Optional[str]) -> NormalizedDomain:
    """Validate and canonicalise a domain, or raise ``DomainValidationError``."""
    if raw is None or not str(raw).strip():
        raise DomainValidationError("EMPTY_INPUT", "Please enter a domain name.")

    raw = str(raw)
    if len(raw) > MAX_RAW_INPUT_LENGTH:
        raise DomainValidationError(
            "INPUT_TOO_LARGE",
            "Input exceeds {} characters.".format(MAX_RAW_INPUT_LENGTH),
        )

    host, was_url = _extract_host(raw)
    if not host:
        raise DomainValidationError("EMPTY_INPUT", "Please enter a domain name.")

    host, is_punycode = _to_ascii(host)
    host = host.rstrip(".").lower()

    if not host:
        raise DomainValidationError("EMPTY_INPUT", "Please enter a domain name.")

    # An IP literal is a legitimate thing to see in DNS telemetry, so we accept
    # and label it rather than rejecting it.
    try:
        ipaddress.ip_address(host)
        return NormalizedDomain(
            original_input=raw.strip(),
            domain=host,
            labels=[host],
            tld="",
            registrable_domain=host,
            sld=host,
            public_suffix="",
            is_ip_literal=True,
            was_url=was_url,
        )
    except ValueError:
        pass

    if len(host) > MAX_DOMAIN_LENGTH:
        raise DomainValidationError(
            "DOMAIN_TOO_LONG",
            "Domain names cannot exceed {} characters (got {}).".format(
                MAX_DOMAIN_LENGTH, len(host)
            ),
        )

    labels = host.split(".")
    for label in labels:
        if not label:
            raise DomainValidationError(
                "EMPTY_LABEL", "Domain contains an empty label (consecutive dots)."
            )
        if len(label) > MAX_LABEL_LENGTH:
            raise DomainValidationError(
                "LABEL_TOO_LONG",
                "The label '{}...' exceeds {} characters.".format(
                    label[:20], MAX_LABEL_LENGTH
                ),
            )
        if not _LABEL_RE.match(label):
            raise DomainValidationError(
                "INVALID_LABEL_FORMAT",
                "The label '{}' contains characters that are not valid in a "
                "domain name, or starts/ends with a hyphen.".format(label[:40]),
            )

    if len(labels) > 1 and _ALL_NUMERIC_RE.match(labels[-1]):
        raise DomainValidationError(
            "NUMERIC_TLD", "A top-level domain cannot be entirely numeric."
        )

    is_single_label = len(labels) == 1
    if is_single_label:
        suffix = ""
        registrable = host
        sld = host
        tld = ""
        subdomain = ""
    else:
        suffix = _public_suffix(labels)
        suffix_label_count = len(suffix.split("."))
        registrable_labels = labels[-(suffix_label_count + 1):]
        registrable = ".".join(registrable_labels)
        sld = registrable_labels[0]
        tld = labels[-1]
        subdomain = ".".join(labels[: -(suffix_label_count + 1)])

    return NormalizedDomain(
        original_input=raw.strip(),
        domain=host,
        labels=labels,
        tld=tld,
        registrable_domain=registrable,
        sld=sld,
        subdomain=subdomain,
        public_suffix=suffix,
        is_ip_literal=False,
        is_punycode=is_punycode,
        is_single_label=is_single_label,
        has_underscore="_" in host,
        was_url=was_url,
    )
