"""Turn extracted capture queries into a threat report.

No detection happens here. Every verdict comes from the same pipeline the
live resolver uses, which is the point: a domain judged from a capture gets
the verdict it would have got at the resolver, by the same code, and the
report can be audited against a single-domain analysis of the same name.

Two deliberate choices:

* Unique names are analysed once each. A capture of one host retrying a
  failing lookup two thousand times is two thousand queries and one decision,
  and scoring it two thousand times would only inflate the timing figure.
* Nothing is written to the event store. A capture is somebody else's
  traffic; recording it as this resolver's history would corrupt the
  behavioural detector, which scores a domain by what it has been seen doing
  here.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.normalizer import DomainValidationError
from ..core.pipeline import get_pipeline

# A capture is untrusted input. Analysing every unique name in a large one
# would tie up the request; the cap is reported so the number is never
# silently partial.
MAX_UNIQUE_DOMAINS = 750


@dataclass
class CaptureQuery:
    """One query taken from a capture, whatever the source format."""

    domain: str
    query_type: str = "A"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: Optional[float] = None
    is_response: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


def _counts_for(source: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "queries": 0,
        "blocked": 0,
        "monitored": 0,
        "allowed": 0,
        "unique_domains": set(),
        **source,
    }


def analyse_capture(queries: List[CaptureQuery], origin: str) -> Dict[str, Any]:
    """Score every distinct name in ``queries`` and aggregate the result."""
    started = time.perf_counter()
    pipeline = get_pipeline()

    questions = [q for q in queries if not q.is_response]
    # A capture with only responses still has names worth judging.
    if not questions:
        questions = list(queries)

    ordered_unique: List[str] = []
    seen = set()
    for query in questions:
        key = query.domain.lower().rstrip(".")
        if key and key not in seen:
            seen.add(key)
            ordered_unique.append(query.domain)

    truncated = len(ordered_unique) > MAX_UNIQUE_DOMAINS
    to_analyse = ordered_unique[:MAX_UNIQUE_DOMAINS]

    verdicts: Dict[str, Dict[str, Any]] = {}
    failures: List[Dict[str, str]] = []
    for domain in to_analyse:
        try:
            result = pipeline.analyse(domain)
        except DomainValidationError as exc:
            failures.append({"domain": domain, "code": exc.code, "message": exc.message})
            continue
        except Exception as exc:                        # pragma: no cover
            failures.append({"domain": domain, "code": "ANALYSIS_ERROR",
                             "message": type(exc).__name__})
            continue

        assessment = result.assessment
        codes = {f.code for f in assessment.factors}
        tunnel = result.signal_named("tunnel")
        dga = result.signal_named("dga")
        classification = result.features.classification

        verdicts[domain.lower().rstrip(".")] = {
            "domain": result.normalized.domain,
            "registrable_domain": result.normalized.registrable_domain,
            "name_kind": classification.kind.value if classification else None,
            "risk_score": assessment.score,
            "classification": assessment.classification,
            "decision": assessment.decision,
            "threat_intel": result.intel_metadata.get("verdict", "UNKNOWN"),
            "dga_score": round((dga.score if dga else 0.0), 1),
            "dga_detected": bool({"DGA_HIGH", "DGA_MODERATE"} & codes),
            "tunnel_score": round((tunnel.score if tunnel else 0.0), 1),
            "tunnel_detected": bool(tunnel and tunnel.metadata.get("indicators")),
            "tunnel_indicators": (tunnel.metadata.get("indicators") if tunnel else []) or [],
            "reason": assessment.factors[0].label if assessment.factors else "",
        }

    # -- per-source-IP telemetry, from the capture itself --------------------
    sources: Dict[str, Dict[str, Any]] = {}
    per_type: Dict[str, int] = {}
    for query in questions:
        key = query.domain.lower().rstrip(".")
        verdict = verdicts.get(key)
        per_type[query.query_type] = per_type.get(query.query_type, 0) + 1
        ip = query.source_ip or "unknown"
        bucket = sources.setdefault(ip, _counts_for({"source_ip": ip}))
        bucket["queries"] += 1
        bucket["unique_domains"].add(key)
        if verdict:
            decision = verdict["decision"]
            if decision == "BLOCK":
                bucket["blocked"] += 1
            elif decision == "MONITOR":
                bucket["monitored"] += 1
            else:
                bucket["allowed"] += 1

    source_rows = []
    for bucket in sources.values():
        total = bucket["queries"] or 1
        source_rows.append({
            "source_ip": bucket["source_ip"],
            "queries": bucket["queries"],
            "unique_domains": len(bucket["unique_domains"]),
            "blocked": bucket["blocked"],
            "monitored": bucket["monitored"],
            "allowed": bucket["allowed"],
            "threat_rate": round(100.0 * bucket["blocked"] / total, 1),
        })
    source_rows.sort(key=lambda r: (-r["blocked"], -r["queries"]))

    judged = list(verdicts.values())
    blocked = [v for v in judged if v["decision"] == "BLOCK"]
    monitored = [v for v in judged if v["decision"] == "MONITOR"]

    return {
        "origin": origin,
        "analysed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "processing_time_ms": round((time.perf_counter() - started) * 1000, 2),
        "total_dns_queries": len(questions),
        "unique_domains": len(ordered_unique),
        "domains_analysed": len(judged),
        "truncated": truncated,
        "truncation_note": (
            "Only the first {} unique names were analysed; the capture "
            "contained {}.".format(MAX_UNIQUE_DOMAINS, len(ordered_unique))
            if truncated else None
        ),
        "malicious_domains": len([v for v in judged if v["classification"] == "MALICIOUS"]),
        "suspicious_domains": len([v for v in judged if v["classification"] == "SUSPICIOUS"]),
        "safe_domains": len([v for v in judged if v["classification"] == "SAFE"]),
        "block_recommendations": len(blocked),
        "monitor_recommendations": len(monitored),
        "dga_detections": len([v for v in judged if v["dga_detected"]]),
        "tunnelling_detections": len([v for v in judged if v["tunnel_detected"]]),
        "threat_intel_hits": len([v for v in judged
                                  if v["threat_intel"] in ("MALICIOUS", "SUSPICIOUS")]),
        "source_ips": source_rows,
        "source_ip_count": len(source_rows),
        "by_query_type": dict(sorted(per_type.items(), key=lambda kv: -kv[1])),
        "findings": sorted(judged, key=lambda v: -v["risk_score"])[:100],
        "rejected": failures[:25],
        "rejected_count": len(failures),
    }
