"""Event persistence and dashboard aggregations.

Every analysis writes one row. Every number the dashboard displays is computed
here from those rows - there are no hardcoded statistics anywhere in the
frontend.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ..config import get_risk_config
from ..core.pipeline import AnalysisResult
from .db import connect, ensure_initialised

ATTRIBUTION_NOTE = (
    "Attribution only. Risk scoring uses domain-wide history, so this "
    "never changes a verdict."
)

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from ..dns_gateway.models import DNSContext

RISK_BUCKETS = [
    (0, 9), (10, 19), (20, 29), (30, 39), (40, 49),
    (50, 59), (60, 69), (70, 79), (80, 89), (90, 100),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventRepository:
    """Reads and writes analysis events."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        ensure_initialised(path)

    # -- writes -------------------------------------------------------------

    def log(
        self,
        result: AnalysisResult,
        source: str = "api",
        dns: Optional["DNSContext"] = None,
    ) -> int:
        """Persist one analysis and return its event id.

        ``dns`` carries the DNS-layer half of a gateway event. When it is None
        this is a plain analysis request from the API or dashboard. Both kinds
        live in one table so the dashboard sees a single event stream, with
        ``event_type`` distinguishing them.
        """
        assessment = result.assessment
        intel = result.intel_metadata
        dga = result.dga_metadata
        lexical = result.signal_named("lexical")

        top_factors = [
            {
                "code": f.code,
                "label": f.label,
                "severity": f.severity.value,
                "contribution": round(f.contribution, 2),
            }
            for f in assessment.factors
            if f.contribution > 0
        ][:5]

        with connect(self.path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    ts_utc, domain, registrable_domain, risk_score,
                    classification, decision, confidence, ti_verdict,
                    ti_categories, ti_indicator, dga_score, lexical_score,
                    analysis_time_ms, top_factors, overrides_applied,
                    features, source, name_kind,
                    event_type, query_type, query_class, client_address,
                    blocked, upstream_used, cache_hit, response_code,
                    block_policy, dns_upstream_time_ms, total_gateway_time_ms
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    _utc_now(),
                    result.normalized.domain,
                    result.normalized.registrable_domain,
                    assessment.score,
                    assessment.classification,
                    assessment.decision,
                    round(assessment.confidence, 3),
                    intel.get("verdict", "UNKNOWN"),
                    json.dumps(intel.get("categories", [])),
                    intel.get("matched_indicator"),
                    round(float(dga.get("score", 0.0)), 4),
                    round(lexical.score if lexical else 0.0, 2),
                    result.total_ms,
                    json.dumps(top_factors),
                    json.dumps(assessment.overrides_applied),
                    json.dumps(result.features.to_dict()),
                    source,
                    (
                        result.features.classification.kind.value
                        if result.features.classification
                        else None
                    ),
                    "dns" if dns else "analysis",
                    dns.query_type if dns else None,
                    dns.query_class if dns else None,
                    dns.client_address if dns else None,
                    1 if (dns and dns.blocked) else 0,
                    1 if (dns and dns.upstream_used) else 0,
                    1 if (dns and dns.cache_hit) else 0,
                    dns.response_code if dns else None,
                    dns.block_policy if dns else None,
                    round(dns.dns_upstream_time_ms, 3) if dns else None,
                    round(dns.total_gateway_time_ms, 3) if dns else None,
                ),
            )
            return int(cursor.lastrowid)

    def clear(self) -> int:
        """Delete every event. Used to reset between demo runs."""
        with connect(self.path) as connection:
            cursor = connection.execute("DELETE FROM events")
            return cursor.rowcount

    # -- reads --------------------------------------------------------------

    @staticmethod
    def _row_to_event(row) -> Dict[str, Any]:
        keys = dict(row)
        return {
            "id": row["id"],
            "timestamp": row["ts_utc"],
            "domain": row["domain"],
            "registrable_domain": row["registrable_domain"],
            "risk_score": row["risk_score"],
            "classification": row["classification"],
            "decision": row["decision"],
            "confidence": row["confidence"],
            "threat_intelligence_verdict": row["ti_verdict"],
            "threat_categories": json.loads(row["ti_categories"]),
            "matched_indicator": row["ti_indicator"],
            "dga_score": row["dga_score"],
            "lexical_score": row["lexical_score"],
            "analysis_time_ms": row["analysis_time_ms"],
            "top_factors": json.loads(row["top_factors"]),
            "overrides_applied": json.loads(row["overrides_applied"]),
            "source": row["source"],
            "event_type": keys.get("event_type") or "analysis",
            "query_type": keys.get("query_type"),
            "query_class": keys.get("query_class"),
            "client_address": keys.get("client_address"),
            "blocked": bool(keys.get("blocked") or 0),
            "upstream_used": bool(keys.get("upstream_used") or 0),
            "cache_hit": bool(keys.get("cache_hit") or 0),
            "response_code": keys.get("response_code"),
            "block_policy": keys.get("block_policy"),
            "dns_upstream_time_ms": keys.get("dns_upstream_time_ms"),
            "total_gateway_time_ms": keys.get("total_gateway_time_ms"),
        }

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: Optional[str] = None,
        decision: Optional[str] = None,
        query: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type.lower())

        if classification:
            clauses.append("classification = ?")
            params.append(classification.upper())
        if decision:
            clauses.append("decision = ?")
            params.append(decision.upper())
        if query:
            clauses.append("domain LIKE ?")
            params.append("%{}%".format(query.lower().strip()))

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        with connect(self.path) as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS n FROM events" + where, params
            ).fetchone()["n"]

            rows = connection.execute(
                "SELECT * FROM events"
                + where
                + " ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

        return {
            "events": [self._row_to_event(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def get_event(self, event_id: int) -> Optional[Dict[str, Any]]:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._row_to_event(row) if row else None

    # -- aggregations -------------------------------------------------------

    def stats(self, activity_hours: int = 24) -> Dict[str, Any]:
        """Everything the dashboard displays, computed from stored events."""
        with connect(self.path) as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS n FROM events"
            ).fetchone()["n"]

            by_classification = {
                row["classification"]: row["n"]
                for row in connection.execute(
                    "SELECT classification, COUNT(*) AS n FROM events "
                    "GROUP BY classification"
                )
            }
            by_decision = {
                row["decision"]: row["n"]
                for row in connection.execute(
                    "SELECT decision, COUNT(*) AS n FROM events GROUP BY decision"
                )
            }
            by_ti_verdict = {
                row["ti_verdict"]: row["n"]
                for row in connection.execute(
                    "SELECT ti_verdict, COUNT(*) AS n FROM events GROUP BY ti_verdict"
                )
            }

            timing = connection.execute(
                "SELECT AVG(analysis_time_ms) AS mean, "
                "MIN(analysis_time_ms) AS fastest, "
                "MAX(analysis_time_ms) AS slowest FROM events"
            ).fetchone()

            times = [
                r["analysis_time_ms"]
                for r in connection.execute(
                    "SELECT analysis_time_ms FROM events ORDER BY analysis_time_ms"
                )
            ]

            distribution = []
            for low, high in RISK_BUCKETS:
                count = connection.execute(
                    "SELECT COUNT(*) AS n FROM events "
                    "WHERE risk_score BETWEEN ? AND ?",
                    (low, high),
                ).fetchone()["n"]
                distribution.append(
                    {"range": "{}-{}".format(low, high), "min": low, "count": count}
                )

            top_domains = [
                {
                    "domain": r["domain"],
                    "risk_score": r["risk_score"],
                    "classification": r["classification"],
                    "hits": r["hits"],
                }
                for r in connection.execute(
                    "SELECT domain, MAX(risk_score) AS risk_score, "
                    "classification, COUNT(*) AS hits FROM events "
                    "WHERE risk_score >= 30 GROUP BY domain "
                    "ORDER BY risk_score DESC, hits DESC LIMIT 10"
                )
            ]

            category_rows = connection.execute(
                "SELECT ti_categories FROM events WHERE ti_categories != '[]'"
            ).fetchall()

            since = (
                datetime.now(timezone.utc) - timedelta(hours=activity_hours)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            activity_rows = connection.execute(
                "SELECT ts_utc, classification FROM events WHERE ts_utc >= ? "
                "ORDER BY ts_utc",
                (since,),
            ).fetchall()

        categories: Dict[str, int] = {}
        for row in category_rows:
            for category in json.loads(row["ti_categories"]):
                if category == "allowlisted":
                    continue
                categories[category] = categories.get(category, 0) + 1

        # Bucket recent activity by hour.
        buckets: Dict[str, Dict[str, int]] = {}
        for row in activity_rows:
            hour = row["ts_utc"][:13] + ":00Z"
            bucket = buckets.setdefault(
                hour, {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
            )
            bucket[row["classification"]] = bucket.get(row["classification"], 0) + 1

        activity = [
            {"hour": hour, **counts} for hour, counts in sorted(buckets.items())
        ]

        p95 = times[int(len(times) * 0.95)] if times else 0.0

        safe = by_classification.get("SAFE", 0)
        suspicious = by_classification.get("SUSPICIOUS", 0)
        malicious = by_classification.get("MALICIOUS", 0)

        return {
            "total_analyzed": total,
            "allowed": by_decision.get("ALLOW", 0),
            "monitored": by_decision.get("MONITOR", 0),
            "blocked": by_decision.get("BLOCK", 0),
            "threats_detected": suspicious + malicious,
            "by_classification": {
                "SAFE": safe,
                "SUSPICIOUS": suspicious,
                "MALICIOUS": malicious,
            },
            "by_decision": {
                "ALLOW": by_decision.get("ALLOW", 0),
                "MONITOR": by_decision.get("MONITOR", 0),
                "BLOCK": by_decision.get("BLOCK", 0),
            },
            "by_threat_intel_verdict": by_ti_verdict,
            "risk_distribution": distribution,
            "threat_categories": dict(
                sorted(categories.items(), key=lambda kv: -kv[1])
            ),
            "top_risky_domains": top_domains,
            "activity": activity,
            "performance": {
                "mean_analysis_time_ms": round(timing["mean"] or 0.0, 3),
                "p95_analysis_time_ms": round(p95, 3),
                "fastest_ms": round(timing["fastest"] or 0.0, 3),
                "slowest_ms": round(timing["slowest"] or 0.0, 3),
                "note": "Measured server-side with perf_counter over the full "
                "analysis pipeline. Excludes network time.",
            },
        }


    _HISTORY_COLUMNS = (
        "COUNT(*) AS total, "
        "COUNT(DISTINCT domain) AS distinct_names, "
        "COALESCE(MAX(risk_score), 0) AS max_risk, "
        "COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) AS blocked, "
        "COALESCE(SUM(CASE WHEN response_code = 'NXDOMAIN' AND blocked = 0 "
        "               THEN 1 ELSE 0 END), 0) AS nxdomain "
    )

    @staticmethod
    def _window_start(window_minutes: int) -> str:
        return (
            datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def domain_history(
        self,
        registrable_domain: str,
        window_minutes: int = 60,
        client_address: Optional[str] = None,
    ):
        """Recent activity for one registrable domain.

        Feeds the behavioural analyser. Deliberately narrow and indexed - this
        runs on the DNS hot path, once per query.

        With no ``client_address`` this counts every event for the domain,
        which is what the risk engine reads: fusion stays domain-wide so that
        evidence spread across several devices is not split below a threshold
        one device alone would have tripped.

        With a ``client_address`` the same counts are narrowed to one client,
        for attribution only. Two exclusions matter there and are deliberate:
        analysis events are dropped because an API request has no client to
        attribute it to, and rows whose address was withheld by the privacy
        policy simply do not match - an unrecorded address is absent, not a
        client with no behaviour, and must never be folded into another one.
        """
        since = self._window_start(window_minutes)

        where = "registrable_domain = ? AND ts_utc >= ?"
        params = [registrable_domain, since]
        if client_address is not None:
            where += " AND client_address = ? AND event_type = 'dns'"
            params.append(client_address)

        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT " + self._HISTORY_COLUMNS + "FROM events WHERE " + where,
                tuple(params),
            ).fetchone()

        return {
            "total_queries": row["total"] or 0,
            "distinct_names": row["distinct_names"] or 0,
            "max_risk_score": row["max_risk"] or 0,
            "blocked_count": row["blocked"] or 0,
            "nxdomain_count": row["nxdomain"] or 0,
        }

    def domain_history_pair(
        self,
        registrable_domain: str,
        client_address: str,
        window_minutes: int = 60,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Domain-wide and client-scoped slices of one domain, in one pass.

        The gateway needs both on the hot path: the first decides the score,
        the second says which device produced the behaviour. Asking twice cost
        two connections and two scans per DNS query - measurably more than the
        analysis it was supporting - so the client half is computed here as
        conditional aggregation over the same rows.

        The client half applies exactly the filters ``domain_history`` applies
        for a client: DNS events only, and only rows whose address was actually
        recorded.
        """
        since = self._window_start(window_minutes)
        scoped = "client_address = ? AND event_type = 'dns'"

        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT "
                + self._HISTORY_COLUMNS
                + ", SUM(CASE WHEN " + scoped + " THEN 1 ELSE 0 END) AS c_total, "
                "COUNT(DISTINCT CASE WHEN " + scoped + " THEN domain END) "
                "    AS c_distinct_names, "
                "COALESCE(MAX(CASE WHEN " + scoped + " THEN risk_score END), 0) "
                "    AS c_max_risk, "
                "COALESCE(SUM(CASE WHEN " + scoped + " AND blocked = 1 "
                "             THEN 1 ELSE 0 END), 0) AS c_blocked, "
                "COALESCE(SUM(CASE WHEN " + scoped + " AND response_code = 'NXDOMAIN' "
                "             AND blocked = 0 THEN 1 ELSE 0 END), 0) AS c_nxdomain "
                "FROM events WHERE registrable_domain = ? AND ts_utc >= ?",
                (
                    client_address,
                    client_address,
                    client_address,
                    client_address,
                    client_address,
                    registrable_domain,
                    since,
                ),
            ).fetchone()

        domain_wide = {
            "total_queries": row["total"] or 0,
            "distinct_names": row["distinct_names"] or 0,
            "max_risk_score": row["max_risk"] or 0,
            "blocked_count": row["blocked"] or 0,
            "nxdomain_count": row["nxdomain"] or 0,
        }
        client_scoped = {
            "total_queries": row["c_total"] or 0,
            "distinct_names": row["c_distinct_names"] or 0,
            "max_risk_score": row["c_max_risk"] or 0,
            "blocked_count": row["c_blocked"] or 0,
            "nxdomain_count": row["c_nxdomain"] or 0,
        }
        return domain_wide, client_scoped

    def client_domain_histories(
        self, client_address: str, window_minutes: int = 60
    ) -> Dict[str, Dict[str, Any]]:
        """Every domain this client touched, with its history slice, in one query.

        One statement rather than one per domain, because the dashboard asks
        for this per source row.
        """
        since = self._window_start(window_minutes)
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT registrable_domain, " + self._HISTORY_COLUMNS
                + "FROM events WHERE client_address = ? AND event_type = 'dns' "
                "AND ts_utc >= ? GROUP BY registrable_domain",
                (client_address, since),
            ).fetchall()

        return {
            row["registrable_domain"]: {
                "total_queries": row["total"] or 0,
                "distinct_names": row["distinct_names"] or 0,
                "max_risk_score": row["max_risk"] or 0,
                "blocked_count": row["blocked"] or 0,
                "nxdomain_count": row["nxdomain"] or 0,
            }
            for row in rows
        }

    # -- DNS aggregations ---------------------------------------------------

    def dns_stats(self, recent_hours: int = 24) -> Dict[str, Any]:
        """Statistics over DNS gateway events only.

        Separate from ``stats()`` so the dashboard can distinguish an ANALYSIS
        REQUEST (someone typed a domain into the console) from a DNS REQUEST (a
        real query hit the gateway). Both are real events; conflating them
        would misrepresent what the gateway has actually handled.
        """
        with connect(self.path) as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS n FROM events WHERE event_type = 'dns'"
            ).fetchone()["n"]

            by_decision = {
                row["decision"]: row["n"]
                for row in connection.execute(
                    "SELECT decision, COUNT(*) AS n FROM events "
                    "WHERE event_type = 'dns' GROUP BY decision"
                )
            }
            by_query_type = {
                row["query_type"]: row["n"]
                for row in connection.execute(
                    "SELECT query_type, COUNT(*) AS n FROM events "
                    "WHERE event_type = 'dns' AND query_type IS NOT NULL "
                    "GROUP BY query_type ORDER BY n DESC"
                )
            }
            by_response_code = {
                row["response_code"]: row["n"]
                for row in connection.execute(
                    "SELECT response_code, COUNT(*) AS n FROM events "
                    "WHERE event_type = 'dns' AND response_code IS NOT NULL "
                    "GROUP BY response_code ORDER BY n DESC"
                )
            }

            blocked_domains = [
                {
                    "domain": row["domain"],
                    "query_type": row["query_type"],
                    "risk_score": row["risk_score"],
                    "reason": (json.loads(row["top_factors"]) or [{}])[0].get(
                        "label", "no dominant factor"
                    ),
                    "policy": row["block_policy"],
                    "hits": row["hits"],
                }
                for row in connection.execute(
                    "SELECT domain, query_type, MAX(risk_score) AS risk_score, "
                    "top_factors, block_policy, COUNT(*) AS hits FROM events "
                    "WHERE event_type = 'dns' AND blocked = 1 "
                    "GROUP BY domain ORDER BY hits DESC, risk_score DESC LIMIT 15"
                )
            ]

            timing = connection.execute(
                "SELECT AVG(analysis_time_ms) AS analysis, "
                "AVG(dns_upstream_time_ms) AS upstream, "
                "AVG(total_gateway_time_ms) AS total, "
                "MAX(total_gateway_time_ms) AS slowest FROM events "
                "WHERE event_type = 'dns'"
            ).fetchone()

            upstream_timing = connection.execute(
                "SELECT AVG(dns_upstream_time_ms) AS upstream FROM events "
                "WHERE event_type = 'dns' AND upstream_used = 1 AND cache_hit = 0"
            ).fetchone()

            cache_hits = connection.execute(
                "SELECT COUNT(*) AS n FROM events "
                "WHERE event_type = 'dns' AND cache_hit = 1"
            ).fetchone()["n"]

            since = (
                datetime.now(timezone.utc) - timedelta(hours=recent_hours)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            activity_rows = connection.execute(
                "SELECT ts_utc, decision FROM events "
                "WHERE event_type = 'dns' AND ts_utc >= ? ORDER BY ts_utc",
                (since,),
            ).fetchall()

            gateway_times = [
                r["total_gateway_time_ms"]
                for r in connection.execute(
                    "SELECT total_gateway_time_ms FROM events "
                    "WHERE event_type = 'dns' AND total_gateway_time_ms IS NOT NULL "
                    "ORDER BY total_gateway_time_ms"
                )
            ]

        p95 = gateway_times[int(len(gateway_times) * 0.95)] if gateway_times else 0.0
        p99 = gateway_times[int(len(gateway_times) * 0.99)] if gateway_times else 0.0

        buckets: Dict[str, Dict[str, int]] = {}
        for row in activity_rows:
            hour = row["ts_utc"][:13] + ":00Z"
            bucket = buckets.setdefault(hour, {"ALLOW": 0, "MONITOR": 0, "BLOCK": 0})
            bucket[row["decision"]] = bucket.get(row["decision"], 0) + 1
        activity = [
            {"hour": hour, **counts} for hour, counts in sorted(buckets.items())
        ]

        return {
            "total_dns_requests": total,
            "activity": activity,
            "allowed": by_decision.get("ALLOW", 0),
            "monitored": by_decision.get("MONITOR", 0),
            "blocked": by_decision.get("BLOCK", 0),
            "cache_hits": cache_hits,
            "by_query_type": by_query_type,
            "by_response_code": by_response_code,
            "blocked_domains": blocked_domains,
            "performance": {
                "mean_analysis_time_ms": round(timing["analysis"] or 0.0, 3),
                "mean_upstream_time_ms": round(upstream_timing["upstream"] or 0.0, 3),
                "mean_total_gateway_time_ms": round(timing["total"] or 0.0, 3),
                "p95_total_gateway_time_ms": round(p95, 3),
                "p99_total_gateway_time_ms": round(p99, 3),
                "measured_queries": len(gateway_times),
                "slowest_total_gateway_time_ms": round(timing["slowest"] or 0.0, 3),
                "note": "Analysis, upstream and end-to-end gateway time are "
                        "measured separately with perf_counter. Upstream mean "
                        "excludes cache hits. End-to-end excludes client network "
                        "time.",
            },
        }


    def client_behaviour(
        self, client_address: str, window_minutes: int = 60
    ) -> Dict[str, Any]:
        """Behavioural attribution for one client. Display only.

        Runs the SAME rules the risk engine uses, over this client's slice of
        history, once per registrable domain the client touched, and reports
        the strongest finding. Nothing here reaches fusion: the score that
        decides ALLOW/BLOCK is still computed from domain-wide history, and
        ``used_in_scoring`` says so in the payload rather than leaving a reader
        to assume either way.

        The import is local because the dependency runs the other way round in
        every other file - detection reads storage - and a module-level import
        here would close the loop.
        """
        from ..detection.behavioral import HistoryBehavioralAnalyzer

        # Bound to this repository rather than the process-wide singleton,
        # which resolves to the globally configured store and would answer
        # about a different database than the one being asked.
        analyzer = HistoryBehavioralAnalyzer(repository=self)
        config = get_risk_config()
        min_queries = int(
            config.get("behavioral.thresholds.min_queries_for_evidence", 3)
        )

        histories = self.client_domain_histories(client_address, window_minutes)

        strongest = None
        strongest_domain = None
        for domain, history in histories.items():
            result = analyzer.score_history(history, config, window_minutes)
            if strongest is None or result.score > strongest.score:
                strongest, strongest_domain = result, domain

        if strongest is None:
            return {
                "verdict": "INSUFFICIENT_HISTORY",
                "score": 0.0,
                "confidence": 0.0,
                "indicators": [],
                "query_burst": False,
                "subdomain_fanout": False,
                "high_nxdomain_ratio": False,
                "repeatedly_blocked": False,
                "registrable_domain": None,
                "window_minutes": window_minutes,
                "used_in_scoring": False,
                "note": ATTRIBUTION_NOTE,
            }

        observed = strongest.observations
        fired = set(strongest.indicators)
        if strongest.indicators:
            verdict = "ANOMALOUS"
        elif observed.get("queries_in_window", 0) >= min_queries:
            verdict = "NORMAL"
        else:
            verdict = "INSUFFICIENT_HISTORY"

        return {
            "verdict": verdict,
            "score": round(strongest.score, 2),
            "confidence": round(strongest.confidence, 3),
            "indicators": strongest.indicators,
            "query_burst": "query_burst" in fired,
            "subdomain_fanout": "subdomain_fanout" in fired,
            "high_nxdomain_ratio": "high_nxdomain_ratio" in fired,
            "repeatedly_blocked": "repeatedly_blocked" in fired,
            "registrable_domain": strongest_domain,
            "window_minutes": window_minutes,
            "queries_in_window": observed.get("queries_in_window", 0),
            "distinct_subdomains": observed.get("distinct_subdomains", 0),
            "nxdomain_ratio": observed.get("nxdomain_ratio", 0.0),
            "blocked_before": observed.get("blocked_before", 0),
            "used_in_scoring": False,
            "note": ATTRIBUTION_NOTE,
        }

    def source_ip_stats(self, limit: int = 50) -> Dict[str, Any]:
        """Query volume and block rate per client address.

        Real telemetry, not a projection: the gateway already records the
        client address of every query it answers, subject to the
        ``dns_log_client_ip`` setting. That setting defaults to
        ``loopback_only``, so on a workstation this returns one row for
        127.0.0.1 and on a deployment configured with ``always`` it returns
        one row per client. Both are honest; the caller is told which.
        """
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT client_address AS ip, COUNT(*) AS queries, "
                "COUNT(DISTINCT domain) AS unique_domains, "
                "COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) AS blocked, "
                "COALESCE(SUM(CASE WHEN decision = 'MONITOR' THEN 1 ELSE 0 END), 0) "
                "    AS monitored, "
                "COALESCE(MAX(risk_score), 0) AS max_risk, "
                "MAX(ts_utc) AS last_seen "
                "FROM events WHERE event_type = 'dns' AND client_address IS NOT NULL "
                "GROUP BY client_address ORDER BY blocked DESC, queries DESC "
                "LIMIT ?",
                (limit,),
            ).fetchall()

            unattributed = connection.execute(
                "SELECT COUNT(*) AS n FROM events "
                "WHERE event_type = 'dns' AND client_address IS NULL"
            ).fetchone()["n"]

        sources = []
        for row in rows:
            queries = row["queries"] or 0
            sources.append({
                "source_ip": row["ip"],
                "queries": queries,
                "unique_domains": row["unique_domains"] or 0,
                "blocked": row["blocked"] or 0,
                "monitored": row["monitored"] or 0,
                "max_risk_score": row["max_risk"] or 0,
                "threat_rate": round(100.0 * (row["blocked"] or 0) / queries, 1)
                if queries else 0.0,
                "last_seen": row["last_seen"],
                "behaviour": self.client_behaviour(row["ip"]),
            })

        return {
            "sources": sources,
            "source_count": len(sources),
            "queries_without_client_address": unattributed,
        }


_repository: Optional[EventRepository] = None


def get_event_repository() -> EventRepository:
    global _repository
    if _repository is None:
        _repository = EventRepository()
    return _repository


def set_event_repository(repository: Optional[EventRepository]) -> None:
    """Override the active repository. Used by tests."""
    global _repository
    _repository = repository
