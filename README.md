# AI-Powered Adaptive DNS Security & Threat Intelligence Platform

**Prototype 1** — Smart India Hackathon internal selection.

A DNS security layer that analyses a domain using several independent signals,
fuses them into a 0–100 risk score, and returns an explained
**ALLOW / MONITOR / BLOCK** decision.

> **Scope honesty.** This prototype performs **no DNS resolution and no outbound
> network traffic.** It analyses domain strings offline. See
> [Current vs planned](#current-prototype-vs-planned-extensions) for exactly what
> is and is not implemented.

---

## Quick start

Requires **Python 3.9+**. No Node.js, no database server, no Docker.

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt   # Windows
# source .venv/bin/activate && pip install -r requirements-dev.txt  # macOS/Linux

python run.py
```

Then open:

| | |
|---|---|
| Dashboard | http://127.0.0.1:8000/ |
| API docs (Swagger) | http://127.0.0.1:8000/api/docs |
| Health | http://127.0.0.1:8000/api/health |

Run the tests:

```bash
.venv\Scripts\python.exe -m pytest
```

---

## How a decision is made

```
Domain / DNS request
        ↓
   Normalizer          validate, canonicalise, extract host from a pasted URL
        ↓
Feature extraction     ~25 lexical measurements
        ↓
  ┌─────────────┬──────────────────┬──────────────────┐
  ↓             ↓                  ↓                  ↓
Threat        DGA /            Lexical         (future signals:
intelligence  suspicion        analysis         behavioural,
                                                tunnelling, PCAP)
  └─────────────┴──────────────────┴──────────────────┘
        ↓
   Risk engine         confidence-weighted fusion + policy overrides
        ↓
Risk score 0–100  +  risk factors explaining every point
        ↓
ALLOW / MONITOR / BLOCK
        ↓
   Event logging  →  Security dashboard
```

Every analyzer returns the same `Signal` object (`core/signals.py`), and the
risk engine fuses whatever signals it is handed. **Adding a detector means
writing one class and adding one weight to the config file** — no change to the
risk engine, the API contract, or the dashboard.

### Threat intelligence is one signal, not the whole system

A threat-intelligence **miss is an absence of evidence, not evidence of safety.**
On `UNKNOWN` the provider reports `confidence = 0.0` and is dropped from the
weighted average entirely, so the DGA and lexical signals alone determine the
score. An unlisted domain can therefore still be blocked on its own
characteristics — which is the whole point of adaptive detection, and what
separates this from `if domain in blacklist: block`.

A confirmed high-confidence indicator applies a score **floor**, not a
short-circuit: other signals can still push the score higher.

---

## Configuration

All detection policy lives in **`config/risk_config.json`**. No weight or
threshold is hardcoded anywhere in the Python.

| Signal | Weight |
|---|---|
| Threat intelligence | 0.40 |
| DGA / suspicion | 0.35 |
| Lexical analysis | 0.25 |

| Score | Classification | Decision |
|---|---|---|
| 0–29 | SAFE | ALLOW |
| 30–69 | SUSPICIOUS | MONITOR |
| 70–100 | MALICIOUS | BLOCK |

`GET /api/config` returns the live policy, so the exact rules behind any verdict
can be inspected.

Deployment settings are environment variables: `DNSSEC_HOST`, `DNSSEC_PORT`,
`DNSSEC_DB_PATH`, `DNSSEC_RISK_CONFIG`, `DNSSEC_LOG_LEVEL`.

---

## Project layout

```
config/risk_config.json      all tunable detection policy
backend/app/
  config.py                  settings + policy loader
  schemas.py                 API contract (Pydantic)
  api/routes.py              endpoints
  core/
    normalizer.py            validation + canonicalisation
    features.py              ~25 lexical measurements (no verdicts)
    lexical.py               feature -> explained 0-100 sub-score
    signals.py               Signal / RiskFactor - the shared vocabulary
    data/                    TLD weights, keywords, brands, suffixes, wordlist
  intel/                     threat-intelligence provider  (step 4)
  detection/
    base.py                  DGADetector interface
    heuristic.py             bigram-likelihood suspicion model
    data/bigrams.json        generated model - do not hand-edit
backend/scripts/
  build_bigram_model.py      rebuilds bigrams.json from the corpus
  evaluate_dga.py            held-out separation check (synthetic negatives)
  core/risk_engine.py        signal fusion, overrides, decision
  core/pipeline.py           orchestration + per-stage timing
  storage/db.py              SQLite schema and connections
  storage/events.py          event log + dashboard aggregations
  extensions/                declared interfaces for future components
backend/tests/               pytest suite
backend/scripts/
  seed_demo_events.py        populates the log by running real analyses
  validate_palette.py        data-viz palette validator (Python port)
frontend/
  index.html  css/  js/      static dashboard, zero dependencies
```

## Demo

```bash
python backend/scripts/seed_demo_events.py --reset   # real analyses, not fake rows
python run.py
```

Then open http://127.0.0.1:8000 and work through the three scenarios below.

---

## Current prototype vs planned extensions

### Implemented and working

- Input validation and canonicalisation — pasted URLs, ports, user-info,
  trailing dots, upper case, IDN → punycode, IP literals, single labels,
  underscore labels
- ~25 lexical features: length, label structure, digit ratio, hyphens,
  subdomain depth, Shannon entropy (raw and length-normalised), vowel ratio,
  consonant runs, character-class distribution, character repetition,
  dictionary-word coverage with stemming, TLD abuse weighting, punycode and
  IP-literal detection, brand impersonation (token, typosquat and substring)
- Transparent rule-based lexical scorer producing a 0–100 sub-score where
  **every point is attributed to a named, explained factor**
- Confidence reporting — short domains carry less lexical information and the
  signal says so rather than emitting a falsely precise score
- **Threat-intelligence provider** behind a swappable `ThreatIntelProvider`
  interface, backed by a bundled synthetic dataset (21 indicators, 82 trusted
  domains). Most-specific-wins matching: exact hit, then parent-domain hit,
  stopping at the registrable domain so a query can never match on a public
  suffix alone. A precise malicious indicator overrides a broader allowlist
  entry, so a compromised host on a reputable domain is still caught.
- **DGA / suspicion detector** — a character-bigram language model trained on
  684 legitimate registrable labels. For a candidate label it computes the mean
  per-character log-likelihood ratio between "drawn from the legitimate-domain
  language model" and "drawn uniformly at random", expresses it as a z-score
  against the corpus distribution, and combines it with dictionary-word coverage
  and digit density through a logistic function. Short labels get their bigram
  evidence shrunk, because six character transitions is genuinely weaker
  evidence than fourteen.
- **Risk engine** — confidence-weighted fusion plus five explicit policy
  overrides (threat-intelligence floor, brand-impersonation floor,
  corroboration bonus, suspicious-TLD/DGA bonus, trusted-allowlist ceiling).
  Every factor carries the exact number of points it moved the score, and
  **the contributions always sum to the final score** — asserted by tests.
- **SQLite event logging** — every analysis persists one row; every dashboard
  figure is aggregated from those rows.
- **Security dashboard** — four views (Overview, Domain Analysis, Recent
  Activity, Threat Analytics) with hand-rolled SVG charts. No npm, no CDN,
  works offline.
- Endpoints: `GET /api/health`, `GET /api/config`, `POST /api/analyze`,
  `POST /api/analyze/bulk`, `GET /api/events`, `GET /api/stats`,
  `DELETE /api/events`, plus the per-signal debug endpoints
  `POST /api/debug/features`, `POST /api/intel/lookup`, `POST /api/debug/dga`
- Structured error handling with stable error codes; no stack traces reach the
  client
- 233 passing tests, including the three demonstration scenarios as
  executable assertions (`backend/tests/test_scenarios.py`)

### Planned production extensions (not built)

Live threat-intelligence feeds and STIX/TAXII, a trained ML DGA model, real DNS
resolution and secure transports (DoH/DoT), DNS tunnelling detection, PCAP/Zeek
ingestion, behavioural analysis over query history, caching, and scalable
deployment. Interfaces for these are declared in `backend/app/extensions/`; they
contain **no fake implementations.**

---

## Demonstration scenarios

All three are asserted in `backend/tests/test_scenarios.py`, so "it works on
stage" and "the tests pass" mean the same thing.

| # | Domain | Result |
|---|---|---|
| 1 | `github.com` | 0/100, SAFE, **ALLOW** — trusted allowlist match |
| 2 | `malware-c2-panel.test` | 85/100, MALICIOUS, **BLOCK** — indicator matched, floor applied |
| 3 | `kq3v9z7jx1p8w.info` | 100/100, MALICIOUS, **BLOCK** — *no threat-intelligence match at all* |

Scenario 3 is the one that matters. The domain appears in no dataset, so the
threat-intelligence signal reports `confidence 0.00` and is **excluded from
fusion entirely**. The DGA and lexical signals alone drive it to BLOCK. The
dashboard shows the excluded signal greyed out with the reason spelled out.

Also worth showing: `compromised-host.example.com` blocks even though
`example.com` is allowlisted, and `hdfcbank-netbanking-verify.xyz` scores 69
(MONITOR) on lexical evidence with a *low* DGA score — human-crafted phishing
is not algorithmically generated, which is why more than one signal exists.

## Honesty notes

- The lexical scorer is a **transparent rule-based model**, labelled
  `TRANSPARENT_RULE_BASED` in every API response. It is not machine learning.
- **No accuracy figure is claimed.** The DGA model is a calibrated statistical
  model, labelled `PROTOTYPE_STATISTICAL` in every response, and its `info()`
  reports `accuracy_claimed: null`. `backend/scripts/evaluate_dga.py` retrains on
  80% of the corpus and measures separation on the held-out 20% against locally
  generated DGA-style strings — **a synthetic benchmark, not a real-world
  accuracy figure**, and it must never be quoted as one.
- **A documented blind spot:** dictionary-word DGAs (suppobox/matsnu style,
  which concatenate real English words) are detected at roughly 0.5%. No
  character-frequency model can see them; closing that gap needs a different
  class of model. A test asserts the limitation so it stays visible rather than
  being quietly forgotten.
- Timings reported by the API are measured with `time.perf_counter()` on the
  machine serving the request. Feature extraction currently measures ~0.3–0.6 ms
  locally. No latency target is claimed.
- Lexical features do **not** prove maliciousness. They contribute to a
  probabilistic suspicion signal, weighted at 0.25.
- All malicious indicators used for testing are **synthetic**, using
  RFC 2606 / RFC 6761 reserved namespaces (`.test`, `.invalid`, `.example`) or
  obviously fake labels. No real malicious infrastructure is referenced or
  contacted.
