"""Event persistence and dashboard aggregations.

Every analysis writes one row. Every number the dashboard displays is computed
here from those rows - there are no hardcoded statistics anywhere in the
frontend.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.pipeline import AnalysisResult
from .db import connect, ensure_initialised

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

    def log(self, result: AnalysisResult, source: str = "api") -> int:
        """Persist one analysis and return its event id."""
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
                    features, source
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
        }

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: Optional[str] = None,
        decision: Optional[str] = None,
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []

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
