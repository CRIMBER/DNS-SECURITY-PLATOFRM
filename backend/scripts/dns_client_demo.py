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
import socket
import sys
import time
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
        print("{}  {}  ->  {}  {}  ({:.2f} ms round trip)".format(
            args.domain, args.rdtype, rcode, answer, elapsed))
        return 0

    print("=" * 88)
    print(" Sending real DNS queries to {}/udp".format(target))
    print(" Round-trip times include the client's own socket overhead; the")
    print(" gateway's own measurements are on the dashboard's DNS Security tab.")
    print("=" * 88)
    print("{:34s} {:5s} {:10s} {:>9s}  {}".format(
        "DOMAIN", "TYPE", "RESULT", "RTT", "ANSWER"))
    print("-" * 88)

    blocked = allowed = failed = 0
    for name, rdtype, _note in DEMO_QUERIES:
        try:
            response, elapsed = query_once(
                args.host, args.port, name, rdtype, args.timeout
            )
        except socket.timeout:
            failed += 1
            print("{:34s} {:5s} {:10s} {:>9s}  gateway did not respond".format(
                name[:34], rdtype, "TIMEOUT", "-"))
            continue

        rcode, answer = describe(response)
        if rcode in ("NXDOMAIN", "REFUSED"):
            blocked += 1
        elif rcode == "NOERROR":
            allowed += 1
        else:
            failed += 1
        print("{:34s} {:5s} {:10s} {:>7.2f}ms  {}".format(
            name[:34], rdtype, rcode, elapsed, answer[:36]))

    print("-" * 88)
    print(" {} resolved, {} blocked, {} failed".format(allowed, blocked, failed))
    print()
    print(" A blocked query returned NXDOMAIN and never reached the upstream")
    print(" resolver. Open the dashboard's DNS Security tab to see these exact")
    print(" queries recorded, with the risk factors behind each decision.")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    sys.exit(main())
