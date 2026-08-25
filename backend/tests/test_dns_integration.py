"""End-to-end DNS gateway tests.

These are NOT simulations. Each test binds a real UDP socket, sends real DNS
packets over loopback with a real DNS client, and asserts on the real response
bytes that come back.

No test touches the internet. The upstream is a ``StubUpstreamResolver`` that
records every call, which is what makes the central assertion possible:
**a blocked query produces zero upstream traffic.** A test that only checked
the response code could not tell the difference between "blocked" and
"resolved, then discarded".
"""

import asyncio
import socket

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from backend.app.config import get_settings
from backend.app.core.pipeline import get_pipeline
from backend.app.dns_gateway import (
    DNSCache,
    DNSGateway,
    DNSRequestHandler,
    StubUpstreamResolver,
    get_policy,
)
from backend.app.dns_gateway.models import GatewayStats
from backend.app.storage.events import EventRepository


# -- helpers ----------------------------------------------------------------


def make_answer(query_wire: bytes, address: str = "93.184.216.34", ttl: int = 60) -> bytes:
    """Build a plausible upstream answer for a query. Used by the stub only."""
    query = dns.message.from_wire(query_wire)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    question = query.question[0]

    if question.rdtype == dns.rdatatype.A:
        rdata = address
    elif question.rdtype == dns.rdatatype.AAAA:
        rdata = "2606:2800:220:1:248:1893:25c8:1946"
    elif question.rdtype == dns.rdatatype.TXT:
        rdata = '"v=spf1 -all"'
    elif question.rdtype == dns.rdatatype.MX:
        rdata = "10 mail.example.com."
    elif question.rdtype == dns.rdatatype.NS:
        rdata = "ns1.example.com."
    elif question.rdtype == dns.rdatatype.CNAME:
        rdata = "alias.example.com."
    else:
        return response.to_wire()   # NOERROR / NODATA

    response.answer.append(
        dns.rrset.from_text(question.name, ttl, question.rdclass, question.rdtype, rdata)
    )
    return response.to_wire()


class DNSTestClient:
    """A real UDP DNS client. Sends bytes, reads bytes."""

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.address = (host, port)
        self.timeout = timeout

    def query(self, name: str, rdtype: str = "A") -> dns.message.Message:
        request = dns.message.make_query(name, dns.rdatatype.from_text(rdtype))
        return dns.message.from_wire(self.send_raw(request.to_wire()))

    def send_raw(self, payload: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, self.address)
            return sock.recv(4096)
        finally:
            sock.close()


@pytest.fixture
def gateway_factory(tmp_path):
    """Build and run a real gateway on an ephemeral port."""
    started = []

    def build(resolver=None, block_mode="NXDOMAIN", cache_enabled=False):
        repository = EventRepository(path=tmp_path / "dns_events.db")
        resolver = resolver if resolver is not None else StubUpstreamResolver(
            responder=make_answer
        )
        stats = GatewayStats()
        handler = DNSRequestHandler(
            pipeline=get_pipeline(),
            resolver=resolver,
            policy=get_policy(block_mode),
            cache=DNSCache(enabled=cache_enabled, max_entries=100, max_ttl=60),
            repository=repository,
            upstream_timeout=2.0,
            log_client_ip="loopback_only",
            stats=stats,
        )
        gateway = DNSGateway(handler=handler, host="127.0.0.1", port=0)
        gateway.stats = stats
        started.append((gateway, repository, resolver))
        return gateway, repository, resolver

    yield build

    for gateway, _, _ in started:
        if gateway.running:
            asyncio.get_event_loop().run_until_complete(gateway.stop())


@pytest.fixture
def run_gateway(gateway_factory):
    """Run a gateway inside its own event loop and expose a real client."""
    import contextlib

    @contextlib.contextmanager
    def runner(**kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        gateway, repository, resolver = gateway_factory(**kwargs)
        loop.run_until_complete(gateway.start())

        import threading

        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        client = DNSTestClient(gateway.host, gateway.port)
        try:
            yield client, gateway, repository, resolver
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=3)
            loop.run_until_complete(gateway.stop())
            loop.close()
            asyncio.set_event_loop(None)

    return runner


# -- 1. safe domain ----------------------------------------------------------


class TestSafeDomainIsResolved:
    def test_allow_forwards_upstream_and_returns_the_answer(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("github.com", "A")

            assert response.rcode() == dns.rcode.NOERROR
            assert len(response.answer) == 1
            assert resolver.call_count == 1, "an allowed query must reach upstream"

            event = repo.list_events(event_type="dns")["events"][0]
            assert event["domain"] == "github.com"
            assert event["decision"] == "ALLOW"
            assert event["upstream_used"] is True
            assert event["blocked"] is False


# -- 2. known malicious indicator -------------------------------------------


class TestKnownMaliciousIsBlocked:
    def test_block_returns_nxdomain_and_never_queries_upstream(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("malware-c2-panel.test", "A")

            assert response.rcode() == dns.rcode.NXDOMAIN
            assert response.answer == []
            # The assertion that matters: no upstream traffic whatsoever.
            assert resolver.call_count == 0

    def test_block_event_records_the_reason(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            client.query("ransom-payment-portal.test", "A")
            event = repo.list_events(event_type="dns")["events"][0]

            assert event["blocked"] is True
            assert event["decision"] == "BLOCK"
            assert event["response_code"] == "NXDOMAIN"
            assert event["block_policy"] == "NXDOMAIN"
            assert event["threat_intelligence_verdict"] == "MALICIOUS"
            assert event["top_factors"]

    def test_refused_policy_is_selectable(self, run_gateway):
        with run_gateway(block_mode="REFUSED") as (client, _, _, resolver):
            response = client.query("malware-c2-panel.test", "A")
            assert response.rcode() == dns.rcode.REFUSED
            assert resolver.call_count == 0


# -- 3. unknown suspicious domain -------------------------------------------


class TestUnknownDGADomain:
    """The not-a-blacklist property, enforced on real DNS traffic."""

    def test_unlisted_dga_domain_is_blocked_on_its_own_characteristics(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("kq3v9z7jx1p8w.info", "A")

            assert response.rcode() == dns.rcode.NXDOMAIN
            assert resolver.call_count == 0

            event = repo.list_events(event_type="dns")["events"][0]
            assert event["threat_intelligence_verdict"] == "UNKNOWN"
            assert event["matched_indicator"] is None
            assert event["risk_score"] >= 70
            assert event["dga_score"] > 0.8


# -- 4. unknown legitimate domain -------------------------------------------


class TestUnknownLegitimateDomain:
    def test_unlisted_ordinary_domain_is_allowed(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("some-ordinary-company.com", "A")

            assert response.rcode() == dns.rcode.NOERROR
            assert resolver.call_count == 1

            event = repo.list_events(event_type="dns")["events"][0]
            assert event["threat_intelligence_verdict"] == "UNKNOWN"
            assert event["decision"] == "ALLOW"


# -- 5. multiple query types -------------------------------------------------


class TestQueryTypes:
    @pytest.mark.parametrize("qtype", ["A", "AAAA", "CNAME", "MX", "TXT", "NS"])
    def test_query_types_are_handled_and_recorded(self, run_gateway, qtype):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("github.com", qtype)
            assert response.rcode() == dns.rcode.NOERROR

            event = repo.list_events(event_type="dns")["events"][0]
            assert event["query_type"] == qtype

    @pytest.mark.parametrize("qtype", ["SOA", "SRV", "CAA", "PTR"])
    def test_unusual_query_types_do_not_crash(self, run_gateway, qtype):
        with run_gateway() as (client, gateway, repo, resolver):
            response = client.query("github.com", qtype)
            assert response.rcode() in (dns.rcode.NOERROR, dns.rcode.SERVFAIL)
            # Server is still alive afterwards.
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR


# -- 6. malformed packets ----------------------------------------------------


class TestMalformedInput:
    """The gateway must survive garbage. Liveness afterwards is the assertion."""

    def test_garbage_payload_does_not_kill_the_server(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            try:
                client.send_raw(b"\xde\xad\xbe\xef" + b"\x00" * 12)
            except socket.timeout:
                pass
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR

    def test_runt_packet_is_dropped_and_server_survives(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"\x01\x02", (gateway.host, gateway.port))
            sock.close()
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR
            assert gateway.stats.malformed_packets >= 1

    def test_empty_packet_is_survived(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"", (gateway.host, gateway.port))
            sock.close()
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR

    def test_truncated_header_gets_an_error_not_a_crash(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            # 12-byte header claiming one question, but no question section.
            payload = (1234).to_bytes(2, "big") + b"\x01\x00\x00\x01" + b"\x00" * 6
            try:
                raw = client.send_raw(payload)
                assert dns.message.from_wire(raw).rcode() != dns.rcode.NOERROR
            except (socket.timeout, dns.exception.DNSException):
                pass
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR


# -- 7. upstream failure -----------------------------------------------------


class TestUpstreamFailure:
    def test_upstream_failure_returns_servfail_and_gateway_survives(self, run_gateway):
        failing = StubUpstreamResolver(fail=True)
        with run_gateway(resolver=failing) as (client, gateway, repo, resolver):
            response = client.query("github.com", "A")

            assert response.rcode() == dns.rcode.SERVFAIL
            assert gateway.stats.upstream_failures == 1

            # Still serving: a blocked domain is still correctly blocked.
            blocked = client.query("malware-c2-panel.test", "A")
            assert blocked.rcode() == dns.rcode.NXDOMAIN

    def test_failure_is_recorded_not_hidden(self, run_gateway):
        with run_gateway(resolver=StubUpstreamResolver(fail=True)) as (client, _, repo, _):
            client.query("github.com", "A")
            event = repo.list_events(event_type="dns")["events"][0]
            assert event["response_code"] == "SERVFAIL"


# -- 8. caching --------------------------------------------------------------


class TestCaching:
    def test_second_identical_query_is_served_from_cache(self, run_gateway):
        with run_gateway(cache_enabled=True) as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            client.query("github.com", "A")

            assert resolver.call_count == 1, "second query should not hit upstream"
            assert gateway.stats.cache_hits == 1

    def test_analysis_still_runs_on_a_cache_hit(self, run_gateway):
        """The cache must never bypass the security decision."""
        with run_gateway(cache_enabled=True) as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            client.query("github.com", "A")

            events = repo.list_events(event_type="dns")["events"]
            assert len(events) == 2, "both queries must produce a security event"
            assert all(e["analysis_time_ms"] > 0 for e in events)
            assert events[0]["cache_hit"] is True

    def test_cached_nxdomain_is_logged_as_nxdomain(self, run_gateway):
        """A cache hit must be reported with the rcode it actually carries.

        The client was always served the correct bytes, but the event log
        hardcoded NOERROR on the cache path, so the same query was reported
        differently depending on whether it happened to hit the cache. That
        silently corrupted the response-code analytics.
        """
        def nxdomain(wire):
            query = dns.message.from_wire(wire)
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.NXDOMAIN)
            # A real resolver returns NXDOMAIN with an SOA in the AUTHORITY
            # section. That SOA carries a TTL, which is what makes the
            # response cacheable at all - a bare NXDOMAIN is not cached and
            # would never exercise this path.
            response.authority.append(
                dns.rrset.from_text(
                    "example.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
                    "ns.example. hostmaster.example. 1 7200 3600 1209600 300",
                )
            )
            return response.to_wire()

        resolver = StubUpstreamResolver(responder=nxdomain)
        with run_gateway(resolver=resolver, cache_enabled=True) as (
            client, gateway, repo, _
        ):
            first = client.query("nonexistent-name.example", "A")
            second = client.query("nonexistent-name.example", "A")

            assert first.rcode() == dns.rcode.NXDOMAIN
            assert second.rcode() == dns.rcode.NXDOMAIN, "client bytes were always right"

            events = repo.list_events(event_type="dns")["events"]
            assert len(events) == 2
            cached = next(e for e in events if e["cache_hit"])
            fresh = next(e for e in events if not e["cache_hit"])
            assert fresh["response_code"] == "NXDOMAIN"
            assert cached["response_code"] == "NXDOMAIN", (
                "a cached NXDOMAIN is still an NXDOMAIN"
            )

    def test_different_query_types_are_cached_separately(self, run_gateway):
        with run_gateway(cache_enabled=True) as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            client.query("github.com", "AAAA")
            assert resolver.call_count == 2

    def test_a_cached_domain_can_still_be_blocked(self, run_gateway):
        """Prove a cached answer cannot outlive a policy change."""
        with run_gateway(cache_enabled=True) as (client, gateway, repo, resolver):
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR

            # Simulate the domain becoming malicious by forcing the decision.
            original = gateway.handler.pipeline.analyse

            def blocked_analysis(domain, context=None):
                result = original(domain, context)
                result.assessment.decision = "BLOCK"
                return result

            gateway.handler.pipeline.analyse = blocked_analysis
            try:
                response = client.query("github.com", "A")
                assert response.rcode() == dns.rcode.NXDOMAIN, (
                    "a cached answer must not bypass a new block decision"
                )
            finally:
                gateway.handler.pipeline.analyse = original


# -- 9. policy consistency ---------------------------------------------------


class TestPolicyConsistency:
    def test_same_domain_yields_the_same_decision(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            for _ in range(5):
                client.query("kq3v9z7jx1p8w.info", "A")

            events = repo.list_events(event_type="dns", limit=10)["events"]
            assert len({e["decision"] for e in events}) == 1
            assert len({e["risk_score"] for e in events}) == 1


# -- 10. timings and privacy -------------------------------------------------


class TestMeasurementAndPrivacy:
    def test_timings_are_measured_separately(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            event = repo.list_events(event_type="dns")["events"][0]

            assert event["analysis_time_ms"] > 0
            assert event["total_gateway_time_ms"] > 0
            # End-to-end must account for at least the analysis it contains.
            assert event["total_gateway_time_ms"] >= event["analysis_time_ms"]

    def test_blocked_query_records_no_upstream_time(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            client.query("malware-c2-panel.test", "A")
            event = repo.list_events(event_type="dns")["events"][0]
            assert event["dns_upstream_time_ms"] in (0, 0.0)

    def test_loopback_client_address_is_recorded(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            event = repo.list_events(event_type="dns")["events"][0]
            assert event["client_address"] == "127.0.0.1"

    def test_dns_events_are_distinguishable_from_analysis_events(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            client.query("github.com", "A")
            repo.log(get_pipeline().analyse("example.com"), source="dashboard")

            assert repo.list_events(event_type="dns")["total"] == 1
            assert repo.list_events(event_type="analysis")["total"] == 1
            assert repo.list_events()["total"] == 2


# -- 11. DNS over TCP --------------------------------------------------------


class TestDNSOverTCP:
    """TCP is not optional in practice: a client that receives a truncated
    response is required to retry over TCP, and some clients start there. The
    framing differs; the security policy does not."""

    @staticmethod
    def tcp_query(host, port, name, rdtype="A", timeout=5.0):
        """A real TCP DNS client: 2-byte length prefix, then the message."""
        request = dns.message.make_query(name, dns.rdatatype.from_text(rdtype))
        payload = request.to_wire()

        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            sock.sendall(len(payload).to_bytes(2, "big") + payload)
            header = sock.recv(2)
            if len(header) < 2:
                raise AssertionError("no length prefix in TCP response")
            length = int.from_bytes(header, "big")
            body = b""
            while len(body) < length:
                chunk = sock.recv(length - len(body))
                if not chunk:
                    break
                body += chunk
            return dns.message.from_wire(body)
        finally:
            sock.close()

    def test_allowed_query_resolves_over_tcp(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            assert gateway.tcp is not None and gateway.tcp.running
            response = self.tcp_query(gateway.host, gateway.port, "github.com")
            assert response.rcode() == dns.rcode.NOERROR
            assert len(response.answer) == 1
            assert resolver.call_count == 1

    def test_blocked_query_is_blocked_over_tcp_too(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            response = self.tcp_query(
                gateway.host, gateway.port, "malware-c2-panel.test"
            )
            assert response.rcode() == dns.rcode.NXDOMAIN
            assert resolver.call_count == 0, "blocked means no upstream, on any transport"

    def test_same_policy_on_both_transports(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            over_udp = client.query("kq3v9z7jx1p8w.info", "A")
            over_tcp = self.tcp_query(gateway.host, gateway.port, "kq3v9z7jx1p8w.info")
            assert over_udp.rcode() == over_tcp.rcode() == dns.rcode.NXDOMAIN

    def test_multiple_queries_on_one_connection(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            request = dns.message.make_query("github.com", dns.rdatatype.A).to_wire()
            sock = socket.create_connection((gateway.host, gateway.port), timeout=5)
            try:
                answered = 0
                for _ in range(3):
                    sock.sendall(len(request).to_bytes(2, "big") + request)
                    header = sock.recv(2)
                    length = int.from_bytes(header, "big")
                    body = b""
                    while len(body) < length:
                        body += sock.recv(length - len(body))
                    assert dns.message.from_wire(body).rcode() == dns.rcode.NOERROR
                    answered += 1
                assert answered == 3
            finally:
                sock.close()

    def test_bogus_length_prefix_does_not_crash(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            sock = socket.create_connection((gateway.host, gateway.port), timeout=5)
            try:
                sock.sendall((60000).to_bytes(2, "big") + b"\x00\x01")
            except OSError:
                pass
            finally:
                sock.close()
            # Still serving on both transports.
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR
            assert self.tcp_query(
                gateway.host, gateway.port, "github.com"
            ).rcode() == dns.rcode.NOERROR

    def test_immediate_disconnect_is_survived(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            socket.create_connection((gateway.host, gateway.port), timeout=5).close()
            assert client.query("github.com", "A").rcode() == dns.rcode.NOERROR

    def test_tcp_events_are_logged_like_udp(self, run_gateway):
        with run_gateway() as (client, gateway, repo, resolver):
            self.tcp_query(gateway.host, gateway.port, "ransom-payment-portal.test")
            event = repo.list_events(event_type="dns")["events"][0]
            assert event["domain"] == "ransom-payment-portal.test"
            assert event["blocked"] is True
