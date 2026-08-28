"""Offline capture analysis: PCAP and Zeek dns.log.

The live gateway sees queries as they happen. These readers cover the other
half of the problem statement - handing the same detection pipeline a capture
taken somewhere else, so a network's DNS traffic can be assessed after the
fact without deploying the resolver into it.

Nothing here re-implements detection. Both readers extract query names and
hand them to the existing pipeline, which is why a domain judged from a PCAP
gets exactly the verdict it would get from the live resolver.
"""

from .pcap import PcapFormatError, extract_dns_queries
from .report import CaptureQuery, analyse_capture
from .zeek import ZeekFormatError, read_zeek_dns_log

__all__ = [
    "CaptureQuery",
    "PcapFormatError",
    "ZeekFormatError",
    "analyse_capture",
    "extract_dns_queries",
    "read_zeek_dns_log",
]
