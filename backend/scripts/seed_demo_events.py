"""Populate the event log with real analyses so the dashboard has data.

This runs the genuine pipeline over a list of domains and stores genuine
results - it does not insert fabricated statistics. Every number the dashboard
then shows was computed by the engine.

    python backend/scripts/seed_demo_events.py
    python backend/scripts/seed_demo_events.py --reset
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.normalizer import DomainValidationError  # noqa: E402
from backend.app.core.pipeline import get_pipeline  # noqa: E402
from backend.app.storage.events import get_event_repository  # noqa: E402

# A realistic mix: mostly ordinary traffic, a few known indicators, a few
# unlisted-but-suspicious names.
DOMAINS = [
    # ordinary traffic
    "google.com", "mail.google.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "cloudflare.com", "amazon.in", "flipkart.com",
    "irctc.co.in", "uidai.gov.in", "sbi.co.in", "hdfcbank.com",
    "openai.com", "python.org", "bbc.co.uk", "zomato.com",
    "linkedin.com", "netflix.com", "paytm.com", "nptel.ac.in",
    # known indicators from the local dataset
    "malware-c2-panel.test", "botnet-controller.test",
    "ransom-payment-portal.test", "login.credential-harvest.invalid",
    "secure-bank-verify.invalid", "crypto-airdrop-claim.invalid",
    "dropper-stage2.test", "tunnel-relay-node.test",
    "compromised-host.example.com", "spam-redirect.test",
    "adware-bundle.test", "parked-monetised.test",
    # unlisted, judged on their own characteristics
    "kq3v9z7jx1p8w.info", "xkzqmwvbtrn.xyz", "vhwnxkzptqrjmb.top",
    "zxqvbnmkljhgfd.tk", "p9x2m7k4q1w8z3.buzz", "jdkfhsuwyeb.com",
    "hdfcbank-netbanking-verify.xyz", "paypal-secure-verify.top",
    "microsoft-account-suspended.cf", "paypa1.com",
    "irctc-refund-claim.top", "summerbridge.com",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing events first.")
    args = parser.parse_args()

    pipeline = get_pipeline()
    repository = get_event_repository()

    if args.reset:
        removed = repository.clear()
        print("cleared {} existing events".format(removed))

    counts = {"ALLOW": 0, "MONITOR": 0, "BLOCK": 0}
    failures = 0

    for domain in DOMAINS:
        try:
            result = pipeline.analyse(domain)
        except DomainValidationError as exc:
            print("  skipped {}: {}".format(domain, exc.code))
            failures += 1
            continue
        repository.log(result, source="seed")
        assessment = result.assessment
        counts[assessment.decision] = counts.get(assessment.decision, 0) + 1
        print("  {:34s} {:3d}  {:11s} {}".format(
            domain, assessment.score, assessment.classification, assessment.decision))

    stats = repository.stats()
    print()
    print("seeded {} events ({} failed)".format(len(DOMAINS) - failures, failures))
    print("  allowed={} monitored={} blocked={} threats={}".format(
        stats["allowed"], stats["monitored"], stats["blocked"],
        stats["threats_detected"]))
    print("  mean analysis time {} ms".format(
        stats["performance"]["mean_analysis_time_ms"]))


if __name__ == "__main__":
    main()
