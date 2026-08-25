"""In-memory DNS answer cache.

SAFETY PROPERTY - read this before changing anything here.

    This cache stores upstream ANSWERS. It never stores security DECISIONS.

Every query runs through the full analysis pipeline *before* the cache is
consulted, and the cache is only reached on the ALLOW/MONITOR branch. A domain
that becomes blocked - because threat intelligence updated, a weight changed,
or a threshold moved - is blocked on its very next query, because a blocked
query never reaches this code at all.

The cost of that guarantee is that analysis runs on every query. It is measured
rather than assumed: see ``analysis_time_ms`` on every DNS event.

Keying is on (name, type, class), because ``example.com A`` and
``example.com AAAA`` are different answers. TTL is taken from the shortest TTL
in the upstream response and clamped to a configured maximum.
"""

import logging
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

import dns.message

logger = logging.getLogger("dnssec.gateway.cache")

CacheKey = Tuple[str, int, int]


class DNSCache:
    """Bounded, TTL-aware LRU cache of raw DNS response bytes."""

    def __init__(
        self,
        enabled: bool = True,
        max_entries: int = 2000,
        max_ttl: int = 300,
    ) -> None:
        self.enabled = enabled
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self._entries: "OrderedDict[CacheKey, Tuple[bytes, float]]" = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0

    # -- key handling -------------------------------------------------------

    @staticmethod
    def key_for(name: str, rdtype: int, rdclass: int) -> CacheKey:
        return (name.lower().rstrip("."), int(rdtype), int(rdclass))

    # -- reads / writes -----------------------------------------------------

    def get(self, key: CacheKey, query_id: int) -> Optional[bytes]:
        """Return a cached response rewritten for this query's transaction id.

        The stored bytes carry the transaction id of whichever query first
        populated the entry. The id is the first two octets of the DNS header,
        so serving a cached answer means replacing those two octets - the rest
        of the message is byte-identical and needs no re-serialisation.
        """
        if not self.enabled:
            return None

        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None

        payload, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._entries[key]
            self.expirations += 1
            self.misses += 1
            return None

        self._entries.move_to_end(key)
        self.hits += 1
        return query_id.to_bytes(2, "big") + payload[2:]

    def put(self, key: CacheKey, response_wire: bytes) -> Optional[int]:
        """Store a response. Returns the TTL used, or None if not cached."""
        if not self.enabled or len(response_wire) < 12:
            return None

        ttl = self._response_ttl(response_wire)
        if ttl is None or ttl <= 0:
            return None

        self._entries[key] = (response_wire, time.monotonic() + ttl)
        self._entries.move_to_end(key)

        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
            self.evictions += 1
        return ttl

    def _response_ttl(self, response_wire: bytes) -> Optional[int]:
        """Shortest TTL in the response, clamped to ``max_ttl``.

        A response carrying no records with a TTL (an empty answer, or an
        error) is not cached at all - it is cheap to ask again and wrong to
        pin a negative result without implementing proper negative caching.
        """
        try:
            message = dns.message.from_wire(response_wire)
        except Exception:
            return None

        ttls = [
            rrset.ttl
            for section in (message.answer, message.authority)
            for rrset in section
            if rrset.ttl > 0
        ]
        if not ttls:
            return None
        return max(1, min(min(ttls), self.max_ttl))

    # -- maintenance --------------------------------------------------------

    def clear(self) -> int:
        removed = len(self._entries)
        self._entries.clear()
        return removed

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {
            "enabled": self.enabled,
            "entries": len(self._entries),
            "max_entries": self.max_entries,
            "max_ttl_seconds": self.max_ttl,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "note": "Caches upstream answers only. Security decisions are never "
                    "cached - analysis runs on every query before the cache is "
                    "consulted.",
        }
