#!/usr/bin/env python3
"""Generate an intentionally truncated AMQP 0-9-1 content body frame.

The final content body frame advertises a payload length larger than the bytes
delivered before the TCP connection closes. This exercises BinPAC's handling
of incomplete frame data without asserting or crashing.

Written with OpenAI Codex using Scapy (AI-assisted per AI_POLICY.md).
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Packet, Raw, wrpcap
from scapy.fields import (
    ByteEnumField,
    IntField,
    LongField,
    ShortField,
    StrField,
    StrLenField,
    XByteField,
)

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40001
SERVER_PORT = 5672
BASE_TIME = 1_700_000_100.0


class AMQPFrame(Packet):
    name = "AMQP frame"
    fields_desc = [
        ByteEnumField(
            "frame_type",
            1,
            {
                1: "method",
                2: "content-header",
                3: "content-body",
                8: "heartbeat",
            },
        ),
        ShortField("channel", 0),
        IntField("payload_length", 0),
        StrLenField("data", b"", length_from=lambda pkt: pkt.payload_length),
        XByteField("frame_end", 0xCE),
    ]


class AMQPMethod(Packet):
    name = "AMQP method payload"
    fields_desc = [
        ShortField("class_id", 0),
        ShortField("method_id", 0),
        StrField("arguments", b""),
    ]


class AMQPContentHeader(Packet):
    name = "AMQP content header payload"
    fields_desc = [
        ShortField("class_id", 60),
        ShortField("weight", 0),
        LongField("body_size", 0),
        ShortField("property_flags", 0),
        StrField("properties", b""),
    ]


def shortstr(value):
    return bytes([len(value)]) + value


def empty_table():
    return struct.pack("!I", 0)


def method_frame(channel, class_id, method_id, arguments=b""):
    payload = bytes(
        AMQPMethod(class_id=class_id, method_id=method_id, arguments=arguments)
    )
    return AMQPFrame(
        frame_type=1, channel=channel, payload_length=len(payload), data=payload
    )


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"

    packet = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        packet = packet / Raw(payload)
    return packet


def build_packets():
    client_seq, server_seq = 3000, 4000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    def send(is_orig, payload):
        nonlocal client_seq, server_seq
        if is_orig:
            packets.append(pkt(True, client_seq, server_seq, "PA", payload))
            client_seq += len(payload)
        else:
            packets.append(pkt(False, server_seq, client_seq, "PA", payload))
            server_seq += len(payload)

    send(True, b"AMQP\x00\x00\x09\x01")

    start_args = (
        bytes([0, 9])
        + empty_table()
        + struct.pack("!I", 5)
        + b"PLAIN"
        + struct.pack("!I", 5)
        + b"en_US"
    )
    send(False, bytes(method_frame(0, 10, 10, start_args)))

    publish_args = (
        struct.pack("!H", 0) + shortstr(b"audit") + shortstr(b"truncated") + b"\x00"
    )
    send(True, bytes(method_frame(1, 60, 40, publish_args)))

    header_payload = bytes(AMQPContentHeader(body_size=100))
    send(
        True,
        bytes(
            AMQPFrame(
                frame_type=2,
                channel=1,
                payload_length=len(header_payload),
                data=header_payload,
            )
        ),
    )

    # Claim a 100-byte body but send only a few bytes before closing.
    truncated_payload = b"cut off"
    # Frame type 3, channel 1, payload length 100, then fewer payload bytes
    # than advertised and no frame-end byte.
    send(True, b"\x03\x00\x01" + struct.pack("!I", 100) + truncated_payload)

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
