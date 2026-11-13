#!/usr/bin/env python3
"""Generate an AMQP 0-9-1 trace with connect, declare, consume, publish, and deliver.

The flow includes the AMQP protocol header, connection negotiation, exchange
and queue declaration, a basic.publish with content header/body, a basic.deliver
with content header/body, and heartbeats.

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
CLIENT_PORT = 40000
SERVER_PORT = 5672
BASE_TIME = 1_700_000_000.0

METHOD_FRAME = 1
CONTENT_HEADER_FRAME = 2
CONTENT_BODY_FRAME = 3
HEARTBEAT_FRAME = 8


class AMQPFrame(Packet):
    name = "AMQP frame"
    fields_desc = [
        ByteEnumField(
            "frame_type",
            METHOD_FRAME,
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


class AMQPContentBody(Packet):
    name = "AMQP content body payload"
    fields_desc = [StrField("body", b"")]


def shortstr(value):
    return bytes([len(value)]) + value


def longstr(value):
    return struct.pack("!I", len(value)) + value


def empty_table():
    return struct.pack("!I", 0)


def method_frame(channel, class_id, method_id, arguments=b""):
    method = AMQPMethod(class_id=class_id, method_id=method_id, arguments=arguments)
    payload = bytes(method)
    return AMQPFrame(
        frame_type=METHOD_FRAME,
        channel=channel,
        payload_length=len(payload),
        data=payload,
    )


def content_header_frame(channel, body_size):
    payload = bytes(AMQPContentHeader(body_size=body_size))
    return AMQPFrame(
        frame_type=CONTENT_HEADER_FRAME,
        channel=channel,
        payload_length=len(payload),
        data=payload,
    )


def content_body_frame(channel, body):
    payload = bytes(AMQPContentBody(body=body))
    return AMQPFrame(
        frame_type=CONTENT_BODY_FRAME,
        channel=channel,
        payload_length=len(payload),
        data=payload,
    )


def heartbeat_frame():
    return AMQPFrame(frame_type=HEARTBEAT_FRAME, channel=0, payload_length=0, data=b"")


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
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    def send(is_orig, packet):
        nonlocal client_seq, server_seq
        if is_orig:
            packets.append(pkt(True, client_seq, server_seq, "PA", bytes(packet)))
            client_seq += len(bytes(packet))
        else:
            packets.append(pkt(False, server_seq, client_seq, "PA", bytes(packet)))
            server_seq += len(bytes(packet))

    vhost = b"/audit"
    exchange = b"audit.events"
    queue = b"audit.events"
    routing_key = b"events.raw"
    consumer_tag = b"consumer-1"
    body = b"hello, audit!"

    send(True, b"AMQP\x00\x00\x09\x01")

    # connection.start (server)
    start_args = bytes([0, 9]) + empty_table() + longstr(b"PLAIN") + longstr(b"en_US")
    send(False, method_frame(0, 10, 10, start_args))

    # connection.start-ok (client)
    start_ok_args = (
        empty_table() + shortstr(b"PLAIN") + longstr(b"guest") + shortstr(b"en_US")
    )
    send(True, method_frame(0, 10, 11, start_ok_args))

    # connection.tune / tune-ok
    tune_args = struct.pack("!HIH", 2047, 131072, 60)
    send(False, method_frame(0, 10, 30, tune_args))
    send(True, method_frame(0, 10, 31, tune_args))

    # connection.open / open-ok
    open_args = shortstr(vhost) + shortstr(b"") + b"\x00"
    send(True, method_frame(0, 10, 40, open_args))
    send(False, method_frame(0, 10, 41, shortstr(b"")))

    # channel.open / open-ok
    send(True, method_frame(1, 20, 10, shortstr(b"")))
    send(False, method_frame(1, 20, 11, shortstr(b"")))

    # queue.declare / declare-ok
    queue_args = struct.pack("!H", 0) + shortstr(queue) + b"\x00" + empty_table()
    send(True, method_frame(1, 50, 10, queue_args))
    send(False, method_frame(1, 50, 11, shortstr(queue) + struct.pack("!II", 0, 0)))

    # exchange.declare / declare-ok
    exchange_args = (
        struct.pack("!H", 0)
        + shortstr(exchange)
        + shortstr(b"topic")
        + b"\x00"
        + empty_table()
    )
    send(True, method_frame(1, 40, 10, exchange_args))
    send(False, method_frame(1, 40, 11))

    # basic.consume / consume-ok
    consume_args = (
        struct.pack("!H", 0)
        + shortstr(queue)
        + shortstr(consumer_tag)
        + b"\x02"
        + empty_table()
    )
    send(True, method_frame(1, 60, 20, consume_args))
    send(False, method_frame(1, 60, 21, shortstr(consumer_tag)))

    # basic.publish followed by content header and body
    publish_args = (
        struct.pack("!H", 0) + shortstr(exchange) + shortstr(routing_key) + b"\x00"
    )
    send(True, method_frame(1, 60, 40, publish_args))
    send(True, content_header_frame(1, len(body)))
    send(True, content_body_frame(1, body))

    # basic.deliver followed by content header and body
    deliver_args = (
        shortstr(consumer_tag)
        + struct.pack("!Q", 1)
        + b"\x00"
        + shortstr(exchange)
        + shortstr(routing_key)
    )
    send(False, method_frame(1, 60, 60, deliver_args))
    send(False, content_header_frame(1, len(body)))
    send(False, content_body_frame(1, body))

    send(True, heartbeat_frame())
    send(False, heartbeat_frame())

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
