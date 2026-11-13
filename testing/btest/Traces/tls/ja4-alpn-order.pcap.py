#!/usr/bin/env python3
"""Generate two TLS 1.3 ClientHellos that differ only in ALPN list order.

The two connections have identical cipher suites, extension type order,
supported groups, point formats, signature algorithms, and SNI. Only the
order of the ALPN protocol values changes. JA3 does not include ALPN values,
while JA4 uses the first value's first and last characters in its readable
prefix, so this trace demonstrates that JA4 is more granular than JA3.

Written with OpenAI Codex using Scapy (disclose AI assistance per AI_POLICY.md).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.layers.tls.extensions import (
    ProtocolName,
    ServerName,
    TLS_Ext_ALPN,
    TLS_Ext_ServerName,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SupportedVersion_SH,
)
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

SERVER = "192.0.2.10"
SERVER_PORT = 443
BASE_TIME = 1_700_000_000.0


def make_client_hello(alpns):
    """Build a deterministic ClientHello with one varying ALPN list."""
    hello = TLSClientHello(
        version=0x0303,
        gmt_unix_time=0x11223344,
        random_bytes=bytes(range(28)),
        ciphers=[0x1301, 0x1302, 0xC02B],
        comp=[0],
        ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername="example.com")]),
            TLS_Ext_SupportedGroups(groups=[29, 23]),
            TLS_Ext_SupportedPointFormat(ecpl=[0]),
            TLS_Ext_ALPN(
                protocols=[ProtocolName(protocol=alpn.encode()) for alpn in alpns]
            ),
            TLS_Ext_SignatureAlgorithms(sig_algs=[0x0403, 0x0804, 0x0401]),
            TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]),
        ],
    )
    return TLS(type=22, version=0x0301, len=len(bytes(hello))) / hello


def make_server_hello():
    hello = TLSServerHello(
        version=0x0303,
        gmt_unix_time=0x55667788,
        random_bytes=bytes(range(32)),
        sid=b"",
        cipher=0x1301,
        comp=0,
        ext=[
            TLS_Ext_SupportedVersion_SH(version=0x0304),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ],
    )
    return TLS(type=22, version=0x0301, len=len(bytes(hello))) / hello


def pkt(client, client_port, is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = client, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, client, SERVER_PORT, client_port
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"

    packet = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        packet = packet / Raw(payload)
    return packet


def build_flow(client, client_port, alpns, base_seq):
    client_hello = bytes(make_client_hello(alpns))
    server_hello = bytes(make_server_hello())

    client_seq = base_seq
    server_seq = base_seq + 10_000
    packets = [
        pkt(client, client_port, True, client_seq, 0, "S"),
        pkt(client, client_port, False, server_seq, client_seq + 1, "SA"),
        pkt(client, client_port, True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    packets.append(
        pkt(
            client,
            client_port,
            True,
            client_seq,
            server_seq,
            "PA",
            client_hello,
        )
    )
    client_seq += len(client_hello)

    packets.append(pkt(client, client_port, False, server_seq, client_seq, "A"))
    packets.append(
        pkt(
            client,
            client_port,
            False,
            server_seq,
            client_seq,
            "PA",
            server_hello,
        )
    )
    server_seq += len(server_hello)

    packets.append(pkt(client, client_port, True, client_seq, server_seq, "A"))

    packets.append(pkt(client, client_port, True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(client, client_port, False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(client, client_port, True, client_seq, server_seq, "A"))

    return packets


def build_packets():
    packets = []
    packets += build_flow("192.0.2.1", 40001, ["h2", "http/1.1"], 1000)
    packets += build_flow("192.0.2.2", 40002, ["http/1.1", "h2"], 2000)
    return packets


def main():
    packets = build_packets()

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
