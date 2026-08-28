"""Read a Zeek ``dns.log`` and hand its queries to the detection pipeline.

Zeek already did the packet decoding, so this reader only has to honour the
log's own header. That header is the contract: ``#separator`` states the
delimiter, ``#fields`` names the columns, ``#unset_field`` and ``#empty_field``
say how absent values are spelled. Reading columns by name rather than by
position matters, because a site's dns.log rarely has the stock column set.

TSV only. Zeek's JSON output is detected and reported rather than guessed at.
"""

import codecs
from dataclasses import dataclass
from typing import Dict, List, Optional

# Columns this reader uses, if the log happens to carry them.
_QUERY_FIELDS = ("query",)
_TYPE_FIELDS = ("qtype_name", "qtype")
_SOURCE_FIELDS = ("id.orig_h", "orig_h")
_DEST_FIELDS = ("id.resp_h", "resp_h")
_TIME_FIELDS = ("ts",)
_RCODE_FIELDS = ("rcode_name", "rcode")

MAX_ROWS = 200_000


class ZeekFormatError(ValueError):
    """The bytes are not a Zeek TSV log this reader understands."""


@dataclass(frozen=True)
class ZeekQuery:
    """One DNS query as Zeek recorded it."""

    domain: str
    query_type: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    timestamp: Optional[float]
    rcode: Optional[str]


def _unescape(value: str) -> str:
    r"""Zeek writes the separator escaped, e.g. ``\x09`` for a tab."""
    try:
        return codecs.decode(value, "unicode_escape")
    except Exception:
        return value


def _first_present(row: Dict[str, str], names, unset: str) -> Optional[str]:
    for name in names:
        value = row.get(name)
        if value is not None and value != unset and value != "":
            return value
    return None


def read_zeek_dns_log(data: bytes) -> List[ZeekQuery]:
    """Parse a Zeek dns.log in TSV form.

    Raises ``ZeekFormatError`` when the file is not a Zeek TSV log, rather
    than quietly returning nothing - "no queries found" and "this is the
    wrong file" are different answers and an analyst needs to tell them apart.
    """
    if not data:
        raise ZeekFormatError("The uploaded file is empty.")

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:                                  # pragma: no cover
        raise ZeekFormatError("The file is not text; Zeek logs are UTF-8.")

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        raise ZeekFormatError(
            "This looks like Zeek's JSON output. This reader takes the TSV "
            "format - the one whose header starts with '#separator'."
        )

    separator = "\t"
    unset = "-"
    empty = "(empty)"
    fields: List[str] = []
    path: Optional[str] = None
    rows: List[ZeekQuery] = []

    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("#"):
            parts = line[1:].split(None, 1)
            if not parts:
                continue
            directive = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            if directive == "separator":
                separator = _unescape(value.strip()) or "\t"
            elif directive == "unset_field":
                unset = value.strip()
            elif directive == "empty_field":
                empty = value.strip()
            elif directive == "path":
                path = value.strip()
            elif directive == "fields":
                # The fields line itself is separator-delimited.
                fields = [f for f in value.split(separator) if f] or value.split()
            continue

        if not fields:
            raise ZeekFormatError(
                "No '#fields' header found. A Zeek TSV log names its columns "
                "in that line, and without it the columns cannot be read by "
                "name."
            )
        if len(rows) >= MAX_ROWS:
            break

        values = line.split(separator)
        row = {fields[i]: values[i] for i in range(min(len(fields), len(values)))}
        domain = _first_present(row, _QUERY_FIELDS, unset)
        if not domain or domain == empty:
            continue

        timestamp = _first_present(row, _TIME_FIELDS, unset)
        try:
            when = float(timestamp) if timestamp else None
        except ValueError:
            when = None

        rows.append(
            ZeekQuery(
                domain=domain.rstrip("."),
                query_type=_first_present(row, _TYPE_FIELDS, unset) or "A",
                source_ip=_first_present(row, _SOURCE_FIELDS, unset),
                dest_ip=_first_present(row, _DEST_FIELDS, unset),
                timestamp=when,
                rcode=_first_present(row, _RCODE_FIELDS, unset),
            )
        )

    if not fields:
        raise ZeekFormatError(
            "No '#fields' header found - this does not look like a Zeek TSV log."
        )
    if path is not None and path != "dns" and not rows:
        raise ZeekFormatError(
            "This is a Zeek '{}' log, not a dns log, so it carries no "
            "queries.".format(path)
        )
    return rows
