"""Send real DNS queries at the gateway and print what comes back.

A genuine UDP DNS client - it builds real query packets, sends them over the
network stack, and decodes the real response bytes. Nothing here is simulated.
It exists so the demo does not depend on ``dig`` or ``nslookup`` being
installed, but those work against the gateway equally well:

    dig @127.0.0.1 -p 5353 github.com
    nslookup -port=5353 github.com 127.0.0.1

Usage:
    python backend/scripts/dns_client_demo.py                    # scripted demo
    python backend/scripts/dns_client_demo.py example.com A      # one query
    python backend/scripts/dns_client_demo.py --host 127.0.0.1 --port 5354
"""

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

import dns.message  # noqa: E402
import dns.rcode  # noqa: E402
import dns.rdatatype  # noqa: E402

from backend.app.config import get_settings  # noqa: E402

# Each entry is (domain, record type, what we expect and why).
DEMO_QUERIES = [
    ("github.com", "A", "trusted allowlist -> ALLOW -> resolved upstream"),
    ("wikipedia.org", "A", "trusted allowlist -> ALLOW"),
    ("malware-c2-panel.test", "A", "threat-intel match -> BLOCK, no upstream query"),
    ("ransom-payment-portal.test", "A", "threat-intel match -> BLOCK"),
    ("login.credential-harvest.invalid", "A", "parent-domain match -> BLOCK"),
    ("kq3v9z7jx1p8w.info", "A", "NOT in any dataset -> blocked on its own characteristics"),
    ("xkzqmwvbtrn.xyz", "A", "NOT in any dataset -> blocked on its own characteristics"),
    ("compromised-host.example.com", "A", "specific indicator beats allowlisted parent"),
    ("some-ordinary-company.com", "A", "unlisted but ordinary -> ALLOW"),
    ("github.com", "AAAA", "different record type, same policy"),
    ("github.com", "MX", "non-address record type"),
]


def query_once(host, port, name, rdtype="A", timeout=5.0):
    """Send one real DNS query and return (response, elapsed_ms)."""
    request = dns.message.make_query(name, dns.rdatatype.from_text(rdtype))
    payload = request.to_wire()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.sendto(payload, (host, port))
        raw = sock.recv(4096)
    finally:
        sock.close()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return dns.message.from_wire(raw), elapsed_ms


def fetch_decision(api_base, domain, rdtype):
    """Ask the backend what it actually decided for the newest matching event.

    A DNS client cannot tell "we blocked this" from "the upstream says this
    name does not exist" - both look like NXDOMAIN on the wire. Reporting them
    as the same thing would misrepresent the system, so the true decision is
    read back from the event the gateway recorded.
    """
    url = "{}/api/dns/events?limit=25&q={}".format(api_base, domain)
    try:
        with urllib.request.urlopen(url, timeout=3) as handle:
            events = json.loads(handle.read().decode("utf-8")).get("events", [])
    except (urllib.error.URLError, OSError, ValueError):
        return None
    for event in events:
        if event.get("domain") == domain and event.get("query_type") == rdtype:
            return event
    return None


def verdict_of(event, rcode):
    """A truthful one-word verdict, or an honest 'unknown' if we cannot tell."""
    if event is None:
        return "?", "no event (is the API running?)"
    if event["decision"] == "BLOCK":
        return "BLOCKED", "by gateway policy, no upstream query"
    if rcode == "NXDOMAIN":
        return "ALLOWED", "forwarded; upstream says no such domain"
    if rcode == "SERVFAIL":
        return "ALLOWED", "forwarded; upstream failed"
    return "ALLOWED", "forwarded and resolved"


def describe(response):
    """One-line summary of what the client actually received."""
    rcode = dns.rcode.to_text(response.rcode())
    if not response.answer:
        return rcode, "-"
    parts = []
    for rrset in response.answer:
        for item in rrset:
            parts.append(item.to_text())
    return rcode, ", ".join(parts[:2])


def main():
    settings = get_settings()
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?", help="Query a single domain and exit.")
    parser.add_argument("rdtype", nargs="?", default="A")
    parser.add_argument("--host", default=settings.dns_listen_host)
    parser.add_argument("--port", type=int, default=settings.dns_listen_port)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--api",
        default="http://{}:{}".format(settings.host, settings.port),
        help="Dashboard API, used to read back the gateway's real decision.",
    )
    args = parser.parse_args()

    target = "{}:{}".format(args.host, args.port)

    if args.domain:
        try:
            response, elapsed = query_once(
                args.host, args.port, args.domain, args.rdtype, args.timeout
            )
        except socket.timeout:
            print("No response from {} within {}s. Is the gateway running?".format(
                target, args.timeout))
            return 1
        rcode, answer = describe(response)
        event = fetch_decision(args.api, args.domain, args.rdtype)
        verdict, why = verdict_of(event, rcode)
        print("{}  {}  ->  {}  [{}: {}]  {}  ({:.2f} ms round trip)".format(
            args.domain, args.rdtype, rcode, verdict, why, answer, elapsed))
        return 0

    print("=" * 88)
    print(" Sending real DNS queries to {}/udp".format(target))
    print(" Round-trip times include the client's own socket overhead; the")
    print(" gateway's own measurements are on the dashboard's DNS Security tab.")
    print("=" * 88)
    print("{:30s} {:5s} {:9s} {:8s} {:>9s}  {}".format(
        "DOMAIN", "TYPE", "RCODE", "VERDICT", "RTT", "ANSWER"))
    print("-" * 88)

    blocked = allowed = failed = 0
    for name, rdtype, _note in DEMO_QUERIES:
        try:
            response, elapsed = query_once(
                args.host, args.port, name, rdtype, args.timeout
            )
        except socket.timeout:
            failed += 1
            print("{:30s} {:5s} {:9s} {:8s} {:>9s}  gateway did not respond".format(
                name[:30], rdtype, "TIMEOUT", "-", "-"))
            continue

        rcode, answer = describe(response)
        event = fetch_decision(args.api, name, rdtype)
        verdict, _why = verdict_of(event, rcode)

        # Counted by the gateway's RECORDED decision, never by the response
        # code: an allowed query whose upstream returns NXDOMAIN is not a block.
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            failed += 1

        print("{:30s} {:5s} {:9s} {:8s} {:>7.2f}ms  {}".format(
            name[:30], rdtype, rcode, verdict, elapsed, answer[:30]))

    print("-" * 88)
    print(" {} allowed, {} blocked, {} failed".format(allowed, blocked, failed))
    print()
    print(" VERDICT is the gateway's recorded decision, not a guess from the")
    print(" response code. NXDOMAIN alone is ambiguous: it can mean 'we blocked")
    print(" it' or 'we forwarded it and the upstream says it does not exist'.")
    print(" A BLOCKED query never reached the upstream resolver at all.")
    print()
    print(" Open the dashboard's DNS Security tab to see these exact queries")
    print(" recorded, with the risk factors behind each decision.")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    sys.exit(main())
