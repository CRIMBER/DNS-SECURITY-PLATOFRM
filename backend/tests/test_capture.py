"""Offline capture analysis: PCAP and Zeek dns.log.

The captures in these tests are BUILT, not fixtures shaped to match the
reader: each one is assembled byte by byte to the format spec - libpcap
global header, Ethernet frame, IPv4 header with a real checksum, UDP header,
and a DNS message encoded by dnspython. If the reader disagrees with the
spec, these fail.

The property that matters most is the last class: a domain judged from a
capture must get the same verdict as the same domain judged through
/api/analyze. The capture readers exist to feed the pipeline, not to be a
second opinion.
"""

import struct

import dns.message
import dns.rdatatype
import pytest
from fastapi.testclient import TestClient

from backend.app.capture import (
    PcapFormatError,
    ZeekFormatError,
    analyse_capture,
    extract_dns_queries,
    read_zeek_dns_log,
)
from backend.app.capture.report import CaptureQuery
from backend.app.main import create_app

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


# -- capture construction ----------------------------------------------------


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += struct.unpack("!H", data[i:i + 2])[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


def udp_over_ipv4(src, dst, payload, sport=40000, dport=53):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
    header += _ipv4(src) + _ipv4(dst)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + udp


def ethernet(payload, ethertype=0x0800):
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02" + \
        struct.pack("!H", ethertype) + payload


def dns_wire(domain, qtype="A"):
    return dns.message.make_query(
        domain, dns.rdatatype.from_text(qtype)
    ).to_wire()


def classic_pcap(packets, linktype=LINKTYPE_ETHERNET, endian="<"):
    magic = 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, packet in enumerate(packets):
        out += struct.pack(endian + "IIII", 1700000000 + i, 0,
                           len(packet), len(packet))
        out += packet
    return out


def pcapng(packets, linktype=LINKTYPE_ETHERNET):
    def block(block_type, body):
        total = 12 + len(body)
        pad = (-len(body)) % 4
        total += pad
        return (struct.pack("<II", block_type, total) + body + b"\x00" * pad
                + struct.pack("<I", total))

    shb = block(0x0A0D0D0A,
                struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))
    out = shb + idb
    for packet in packets:
        body = struct.pack("<IIIII", 0, 0, 0, len(packet), len(packet)) + packet
        pad = (-len(packet)) % 4
        out += block(0x00000006, body + b"\x00" * pad)[:  # keep alignment simple
                                                      ] if pad else block(
            0x00000006, body)
    return out


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


# -- PCAP --------------------------------------------------------------------


class TestPcapReader:
    def test_reads_queries_from_a_real_capture(self):
        capture = classic_pcap([
            ethernet(udp_over_ipv4("192.168.1.10", "1.1.1.1",
                                   dns_wire("google.com"))),
            ethernet(udp_over_ipv4("192.168.1.21", "1.1.1.1",
                                   dns_wire("malware-c2-panel.test"))),
        ])
        found = extract_dns_queries(capture)
        assert [q.domain for q in found] == ["google.com", "malware-c2-panel.test"]
        assert found[0].source_ip == "192.168.1.10"
        assert found[1].source_ip == "192.168.1.21"
        assert found[0].transport == "udp"
        assert found[0].query_type == "A"

    def test_record_type_survives(self):
        capture = classic_pcap([
            ethernet(udp_over_ipv4("10.0.0.1", "1.1.1.1",
                                   dns_wire("exfil.example.com", "TXT"))),
        ])
        assert extract_dns_queries(capture)[0].query_type == "TXT"

    def test_non_dns_traffic_is_skipped_not_guessed_at(self):
        """A capture of a real network is mostly other traffic."""
        capture = classic_pcap([
            ethernet(udp_over_ipv4("192.168.1.10", "192.168.1.1", b"not dns",
                                   sport=5000, dport=5001)),
            ethernet(udp_over_ipv4("192.168.1.10", "1.1.1.1",
                                   dns_wire("github.com"))),
            ethernet(b"\x00" * 40, ethertype=0x0806),          # ARP
        ])
        assert [q.domain for q in extract_dns_queries(capture)] == ["github.com"]

    def test_big_endian_capture(self):
        capture = classic_pcap(
            [ethernet(udp_over_ipv4("10.0.0.2", "1.1.1.1", dns_wire("bbc.co.uk")))],
            endian=">",
        )
        # A big-endian file writes the magic the other way round.
        capture = b"\xa1\xb2\xc3\xd4" + capture[4:]
        assert [q.domain for q in extract_dns_queries(capture)] == ["bbc.co.uk"]

    def test_raw_ip_link_type(self):
        capture = classic_pcap(
            [udp_over_ipv4("10.0.0.3", "1.1.1.1", dns_wire("python.org"))],
            linktype=LINKTYPE_RAW,
        )
        assert [q.domain for q in extract_dns_queries(capture)] == ["python.org"]

    def test_pcapng_container(self):
        capture = pcapng([
            ethernet(udp_over_ipv4("192.168.1.10", "1.1.1.1",
                                   dns_wire("wikipedia.org"))),
        ])
        assert [q.domain for q in extract_dns_queries(capture)] == ["wikipedia.org"]

    def test_vlan_tagged_frame(self):
        inner = udp_over_ipv4("192.168.5.5", "1.1.1.1", dns_wire("vlan.example.com"))
        frame = (b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02"
                 + struct.pack("!H", 0x8100) + struct.pack("!H", 0x0064)
                 + struct.pack("!H", 0x0800) + inner)
        assert [q.domain for q in extract_dns_queries(classic_pcap([frame]))] == \
            ["vlan.example.com"]

    @pytest.mark.parametrize("blob,fragment", [
        (b"", "empty"),
        # Long enough to reach the magic-number check rather than the length one.
        (b"this file is definitely not a packet capture at all", "magic"),
        (b"\x00" * 8, "short"),
    ])
    def test_bad_input_is_reported_not_crashed(self, blob, fragment):
        with pytest.raises(PcapFormatError) as caught:
            extract_dns_queries(blob)
        assert fragment in str(caught.value).lower()

    def test_a_truncated_final_record_does_not_crash(self):
        capture = classic_pcap([
            ethernet(udp_over_ipv4("10.0.0.4", "1.1.1.1", dns_wire("ok.example.com")))
        ])
        found = extract_dns_queries(capture + b"\x01\x02\x03")
        assert [q.domain for q in found] == ["ok.example.com"]


# -- Zeek --------------------------------------------------------------------


TAB = "\t"


def zeek_log(rows, fields=None, path="dns"):
    fields = fields or ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name",
                        "rcode_name"]
    lines = [
        "#separator \\x09",
        "#unset_field" + TAB + "-",
        "#empty_field" + TAB + "(empty)",
        "#path" + TAB + path,
        "#fields" + TAB + TAB.join(fields),
    ]
    lines.extend(TAB.join(r) for r in rows)
    lines.append("#close" + TAB + "2026-08-28-00-00-00")
    return ("\n".join(lines) + "\n").encode()


class TestZeekReader:
    def test_reads_queries_by_column_name(self):
        log = zeek_log([
            ["1756370000.1", "192.168.1.10", "1.1.1.1", "google.com", "A", "NOERROR"],
            ["1756370001.2", "192.168.1.21", "1.1.1.1", "botnet-controller.test",
             "A", "NXDOMAIN"],
        ])
        rows = read_zeek_dns_log(log)
        assert [r.domain for r in rows] == ["google.com", "botnet-controller.test"]
        assert rows[0].source_ip == "192.168.1.10"
        assert rows[1].rcode == "NXDOMAIN"
        assert rows[0].timestamp == pytest.approx(1756370000.1)

    def test_columns_are_read_by_name_not_position(self):
        """A site's dns.log rarely has the stock column order."""
        log = zeek_log(
            [["A", "example.com", "192.168.9.9", "1756370000.0"]],
            fields=["qtype_name", "query", "id.orig_h", "ts"],
        )
        row = read_zeek_dns_log(log)[0]
        assert row.domain == "example.com"
        assert row.query_type == "A"
        assert row.source_ip == "192.168.9.9"

    def test_unset_query_rows_are_skipped(self):
        log = zeek_log([
            ["1756370000.0", "192.168.1.10", "1.1.1.1", "-", "A", "NOERROR"],
            ["1756370001.0", "192.168.1.10", "1.1.1.1", "github.com", "A", "NOERROR"],
        ])
        assert [r.domain for r in read_zeek_dns_log(log)] == ["github.com"]

    def test_trailing_dot_is_removed(self):
        log = zeek_log([["1.0", "10.0.0.1", "1.1.1.1", "example.com.", "A", "NOERROR"]])
        assert read_zeek_dns_log(log)[0].domain == "example.com"

    def test_json_output_is_named_rather_than_misparsed(self):
        with pytest.raises(ZeekFormatError) as caught:
            read_zeek_dns_log(b'{"ts":1.0,"query":"example.com"}')
        assert "JSON" in str(caught.value)

    def test_a_file_without_a_fields_header_is_rejected(self):
        with pytest.raises(ZeekFormatError) as caught:
            read_zeek_dns_log(b"just\tsome\ttext\n")
        assert "#fields" in str(caught.value)

    def test_empty_file_is_rejected(self):
        with pytest.raises(ZeekFormatError):
            read_zeek_dns_log(b"")


# -- report ------------------------------------------------------------------


class TestCaptureReport:
    def test_counts_come_from_the_real_pipeline(self):
        report = analyse_capture([
            CaptureQuery(domain="google.com", source_ip="192.168.1.10"),
            CaptureQuery(domain="malware-c2-panel.test", source_ip="192.168.1.21"),
            CaptureQuery(domain="xjqzwvbnmk4d8f2.top", source_ip="192.168.1.21"),
        ], origin="pcap")
        assert report["total_dns_queries"] == 3
        assert report["unique_domains"] == 3
        assert report["domains_analysed"] == 3
        assert report["malicious_domains"] >= 2
        assert report["block_recommendations"] >= 2
        assert report["dga_detections"] >= 1

    def test_repeated_names_are_analysed_once(self):
        queries = [CaptureQuery(domain="github.com", source_ip="10.0.0.1")] * 50
        report = analyse_capture(queries, origin="pcap")
        assert report["total_dns_queries"] == 50
        assert report["unique_domains"] == 1
        assert report["domains_analysed"] == 1

    def test_source_ip_rows_are_derived_from_the_capture(self):
        report = analyse_capture([
            CaptureQuery(domain="google.com", source_ip="192.168.1.10"),
            CaptureQuery(domain="malware-c2-panel.test", source_ip="192.168.1.21"),
            CaptureQuery(domain="botnet-controller.test", source_ip="192.168.1.21"),
        ], origin="pcap")
        rows = {r["source_ip"]: r for r in report["source_ips"]}
        assert rows["192.168.1.21"]["queries"] == 2
        assert rows["192.168.1.21"]["blocked"] == 2
        assert rows["192.168.1.21"]["threat_rate"] == 100.0
        assert rows["192.168.1.10"]["blocked"] == 0

    def test_unparseable_names_are_reported_not_dropped_silently(self):
        report = analyse_capture([
            CaptureQuery(domain="not a domain!!", source_ip="10.0.0.1"),
            CaptureQuery(domain="github.com", source_ip="10.0.0.1"),
        ], origin="pcap")
        assert report["rejected_count"] == 1
        assert report["rejected"][0]["domain"] == "not a domain!!"
        assert report["domains_analysed"] == 1

    def test_a_capture_is_never_written_to_the_event_log(self):
        """A capture is another network's traffic.

        Recording it as this resolver's history would feed the behavioural
        detector evidence about queries this resolver never answered.
        """
        from backend.app.storage.events import get_event_repository

        repository = get_event_repository()
        before = repository.stats()["total_analyzed"]
        analyse_capture(
            [CaptureQuery(domain="botnet-controller.test", source_ip="10.0.0.9")],
            origin="pcap",
        )
        assert repository.stats()["total_analyzed"] == before


class TestCaptureAgreesWithLiveAnalysis:
    """The whole point of the readers: same pipeline, same verdict."""

    @pytest.mark.parametrize("domain", [
        "google.com",
        "malware-c2-panel.test",
        "xjqzwvbnmk4d8f2.top",
        "d111111abcdef8.cloudfront.net",
        "192.168.1.10",
    ])
    def test_capture_verdict_equals_api_verdict(self, client, domain):
        live = client.post("/api/analyze",
                           json={"domain": domain, "source": "capture-parity"}).json()
        report = analyse_capture([CaptureQuery(domain=domain)], origin="pcap")
        finding = report["findings"][0]
        assert finding["risk_score"] == live["risk_score"], domain
        assert finding["decision"] == live["decision"], domain
        assert finding["classification"] == live["classification"], domain


# -- endpoints ---------------------------------------------------------------


class TestCaptureEndpoints:
    def test_pcap_upload_returns_a_report(self, client):
        capture = classic_pcap([
            ethernet(udp_over_ipv4("192.168.1.10", "1.1.1.1", dns_wire("google.com"))),
            ethernet(udp_over_ipv4("192.168.1.21", "1.1.1.1",
                                   dns_wire("malware-c2-panel.test"))),
        ])
        response = client.post("/api/capture/pcap", content=capture)
        assert response.status_code == 200
        body = response.json()
        assert body["origin"] == "pcap"
        assert body["total_dns_queries"] == 2
        assert body["dns_packets_seen"] == 2
        assert body["capture_bytes"] == len(capture)
        assert body["block_recommendations"] >= 1

    def test_zeek_upload_returns_a_report(self, client):
        log = zeek_log([
            ["1.0", "192.168.1.10", "1.1.1.1", "google.com", "A", "NOERROR"],
            ["2.0", "192.168.1.21", "1.1.1.1", "botnet-controller.test", "A",
             "NXDOMAIN"],
        ])
        response = client.post("/api/capture/zeek", content=log)
        assert response.status_code == 200
        body = response.json()
        assert body["origin"] == "zeek"
        assert body["log_rows"] == 2
        assert body["source_ip_count"] == 2

    def test_a_bad_pcap_is_a_400_with_a_readable_reason(self, client):
        response = client.post("/api/capture/pcap", content=b"this is not a capture")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_PCAP"

    def test_a_bad_zeek_log_is_a_400(self, client):
        response = client.post("/api/capture/zeek", content=b'{"json":"output"}')
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_ZEEK_LOG"

    def test_an_empty_upload_is_a_400(self, client):
        response = client.post("/api/capture/pcap", content=b"")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "EMPTY_UPLOAD"

    def test_support_endpoint_states_what_is_implemented(self, client):
        body = client.get("/api/capture/support").json()
        assert body["pcap"]["status"] == "IMPLEMENTED"
        assert body["zeek"]["status"] == "IMPLEMENTED"
        assert body["analysis"]["writes_to_event_log"] is False


class TestTelemetryEndpoints:
    def test_sources_reports_its_own_logging_policy(self, client):
        body = client.get("/api/sources").json()
        assert "sources" in body
        assert body["client_ip_logging"] in ("none", "loopback_only", "always")
        assert body["note"]

    def test_intel_summary_does_not_claim_a_feed_it_lacks(self, client):
        body = client.get("/api/intel/summary").json()
        states = {f["name"]: f["state"] for f in body["feeds"]}
        assert states["Local IOC database"] == "ACTIVE"
        assert states["STIX/TAXII collection"] == "NOT_CONNECTED"
        assert states["Commercial feed"] == "NOT_CONNECTED"
        assert "SYNTHETIC" in body["honesty_note"]

    def test_protocols_marks_only_what_exists(self, client):
        body = client.get("/api/protocols").json()
        states = {p["short"]: p["state"] for p in body["protocols"]}
        assert states["UDP"] in ("ACTIVE", "CONFIGURED")
        assert states["TCP"] in ("ACTIVE", "CONFIGURED")
        assert states["DoT"] == "NOT_IMPLEMENTED"
        assert states["DoH"] == "NOT_IMPLEMENTED"

    def test_dns_stats_reports_p99_alongside_p95(self, client):
        performance = client.get("/api/dns/stats").json()["performance"]
        assert "p95_total_gateway_time_ms" in performance
        assert "p99_total_gateway_time_ms" in performance
        assert "measured_queries" in performance
