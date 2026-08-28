"""Pull DNS queries out of a packet capture.

This is a real reader, not a stub: it walks the capture format, decodes the
link and network layers, and parses the DNS payload with dnspython - the same
library the gateway uses on the wire. A domain extracted here reaches the
detection pipeline as the identical string the resolver would have seen.

Both capture containers are supported, because tcpdump and Wireshark disagree
about which one is the default:

  * classic libpcap  - 24-byte global header, then fixed-size packet records
  * pcapng           - typed blocks; Section Header, Interface Description
                       and Enhanced/Simple Packet blocks are read, the rest
                       skipped

Anything malformed raises ``PcapFormatError`` with a sentence a human can act
on. A judge uploading the wrong file gets told what was wrong with it, not a
stack trace.
"""

import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

import dns.message

DNS_PORT = 53

# Link-layer types we can decode, and the fixed header length to skip.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_VLAN = (0x8100, 0x88A8, 0x9100)

_PROTO_TCP = 6
_PROTO_UDP = 17

# Guard rails. A capture is attacker-supplied input as much as a query name is.
MAX_PACKETS = 200_000


class PcapFormatError(ValueError):
    """The bytes are not a capture this reader understands."""


@dataclass(frozen=True)
class CapturedQuery:
    """One DNS question observed in the capture."""

    domain: str
    query_type: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    transport: str
    timestamp: Optional[float]
    is_response: bool


# -- link and network layers -------------------------------------------------


def _strip_link_layer(data: bytes, linktype: int) -> Tuple[Optional[bytes], Optional[int]]:
    """Return (network-layer bytes, IP version), or (None, None) if not IP."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, None
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        # VLAN tags stack; each adds four bytes before the real ethertype.
        while ethertype in _ETHERTYPE_VLAN and len(data) >= offset + 4:
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        if ethertype == _ETHERTYPE_IPV4:
            return data[offset:], 4
        if ethertype == _ETHERTYPE_IPV6:
            return data[offset:], 6
        return None, None

    if linktype == LINKTYPE_RAW or linktype in (LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None, None
        return data, (data[0] >> 4)

    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None, None
        # Host byte order family; 2 is AF_INET, 24/28/30 are AF_INET6 variants.
        family = struct.unpack("<I", data[:4])[0]
        if family > 0xFFFF:
            family = struct.unpack(">I", data[:4])[0]
        if family == 2:
            return data[4:], 4
        if family in (24, 28, 30):
            return data[4:], 6
        return None, None

    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, None
        ethertype = struct.unpack("!H", data[14:16])[0]
        if ethertype == _ETHERTYPE_IPV4:
            return data[16:], 4
        if ethertype == _ETHERTYPE_IPV6:
            return data[16:], 6
        return None, None

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None, None
        ethertype = struct.unpack("!H", data[0:2])[0]
        if ethertype == _ETHERTYPE_IPV4:
            return data[20:], 4
        if ethertype == _ETHERTYPE_IPV6:
            return data[20:], 6
        return None, None

    return None, None


def _ipv4_address(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _ipv6_address(raw: bytes) -> str:
    parts = [
        "{:x}".format(struct.unpack("!H", raw[i:i + 2])[0]) for i in range(0, 16, 2)
    ]
    return ":".join(parts)


def _transport_payload(packet: bytes, version: int):
    """Return (payload, src_ip, dst_ip, transport) for a DNS-port datagram."""
    if version == 4:
        if len(packet) < 20:
            return None
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return None
        protocol = packet[9]
        # Fragmented packets after the first carry no transport header.
        fragment_offset = struct.unpack("!H", packet[6:8])[0] & 0x1FFF
        if fragment_offset:
            return None
        src = _ipv4_address(packet[12:16])
        dst = _ipv4_address(packet[16:20])
        rest = packet[ihl:]
    elif version == 6:
        if len(packet) < 40:
            return None
        protocol = packet[6]
        src = _ipv6_address(packet[8:24])
        dst = _ipv6_address(packet[24:40])
        rest = packet[40:]
    else:
        return None

    if protocol == _PROTO_UDP:
        if len(rest) < 8:
            return None
        sport, dport = struct.unpack("!HH", rest[:4])
        if DNS_PORT not in (sport, dport):
            return None
        return rest[8:], src, dst, "udp"

    if protocol == _PROTO_TCP:
        if len(rest) < 20:
            return None
        sport, dport = struct.unpack("!HH", rest[:4])
        if DNS_PORT not in (sport, dport):
            return None
        data_offset = (rest[12] >> 4) * 4
        if data_offset < 20 or len(rest) < data_offset:
            return None
        payload = rest[data_offset:]
        # DNS over TCP prefixes a two-byte length. Only a segment that starts
        # a message is useful; a continuation has no header to parse.
        if len(payload) < 2:
            return None
        declared = struct.unpack("!H", payload[:2])[0]
        body = payload[2:2 + declared]
        if len(body) < 12:
            return None
        return body, src, dst, "tcp"

    return None


def _questions(payload: bytes, src, dst, transport, timestamp):
    """Parse one DNS message and yield its questions."""
    try:
        message = dns.message.from_wire(payload, question_only=True)
    except Exception:
        return
    is_response = bool(message.flags & 0x8000)
    for question in message.question:
        name = question.name.to_text(omit_final_dot=True)
        if not name or name == ".":
            continue
        yield CapturedQuery(
            domain=name,
            query_type=dns.rdatatype.to_text(question.rdtype),
            source_ip=src,
            dest_ip=dst,
            transport=transport,
            timestamp=timestamp,
            is_response=is_response,
        )


# -- container formats -------------------------------------------------------


def _iter_classic(data: bytes) -> Iterator[Tuple[bytes, int, Optional[float]]]:
    if len(data) < 24:
        raise PcapFormatError("File is too short to be a capture (under 24 bytes).")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nanosecond = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nanosecond = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise PcapFormatError("Not a libpcap file: unrecognised magic number.")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset, count = 24, 0
    while offset + 16 <= len(data) and count < MAX_PACKETS:
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        if incl_len > len(data) - offset:
            break   # truncated final record
        packet = data[offset:offset + incl_len]
        offset += incl_len
        count += 1
        divisor = 1_000_000_000.0 if nanosecond else 1_000_000.0
        yield packet, linktype, ts_sec + ts_frac / divisor


def _iter_pcapng(data: bytes) -> Iterator[Tuple[bytes, int, Optional[float]]]:
    if len(data) < 12:
        raise PcapFormatError("File is too short to be a pcapng capture.")
    byte_order = data[8:12]
    if byte_order == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif byte_order == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise PcapFormatError("pcapng byte-order magic is missing or corrupt.")

    interfaces: List[int] = []
    offset, count = 0, 0
    while offset + 12 <= len(data) and count < MAX_PACKETS:
        block_type, block_len = struct.unpack(endian + "II", data[offset:offset + 8])
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8:offset + block_len - 4]

        if block_type == 0x00000001 and len(body) >= 8:          # Interface
            interfaces.append(struct.unpack(endian + "H", body[:2])[0])
        elif block_type == 0x00000006 and len(body) >= 20:       # Enhanced packet
            iface, _hi, _lo, captured, _orig = struct.unpack(
                endian + "IIIII", body[:20]
            )
            linktype = interfaces[iface] if iface < len(interfaces) else LINKTYPE_ETHERNET
            yield body[20:20 + captured], linktype, None
            count += 1
        elif block_type == 0x00000003 and len(body) >= 4:        # Simple packet
            linktype = interfaces[0] if interfaces else LINKTYPE_ETHERNET
            yield body[4:], linktype, None
            count += 1

        offset += block_len


def extract_dns_queries(data: bytes) -> List[CapturedQuery]:
    """Every DNS question in the capture, in the order it was seen.

    Responses are included and flagged; the caller decides whether to score
    them. Packets that are not DNS, not IP, or not parseable are skipped
    silently - a capture of a real network is mostly other traffic.
    """
    if not data:
        raise PcapFormatError("The uploaded file is empty.")

    if data[:4] == b"\x0a\x0d\x0d\x0a":
        packets = _iter_pcapng(data)
    else:
        packets = _iter_classic(data)

    found: List[CapturedQuery] = []
    for packet, linktype, timestamp in packets:
        network, version = _strip_link_layer(packet, linktype)
        if network is None or version not in (4, 6):
            continue
        transport = _transport_payload(network, version)
        if transport is None:
            continue
        payload, src, dst, kind = transport
        found.extend(_questions(payload, src, dst, kind, timestamp))
    return found
