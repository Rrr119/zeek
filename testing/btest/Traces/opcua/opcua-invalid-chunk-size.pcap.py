#!/usr/bin/env python3
"""Generate an OPC UA trace with an invalid message-chunk length.

The connection first exchanges a valid Hello/Acknowledge pair, then sends a
secure-channel header whose declared size is smaller than the eight-byte OPC
UA message header. The analyzer must reject the chunk without crashing.

Generated with OpenAI Codex.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
CLIENT_PORT = 49152
SERVER_PORT = 4840
BASE_TIME = 1_700_000_100.0
ENDPOINT_URL = f"opc.tcp://{SERVER_IP}:{SERVER_PORT}"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def opcua_string(value: str) -> bytes:
    encoded = value.encode()
    return i32(len(encoded)) + encoded


def hello() -> bytes:
    body = (
        u32(0) + u32(65535) + u32(65535) + u32(0) + u32(0) + opcua_string(ENDPOINT_URL)
    )
    return b"HELF" + u32(len(body) + 8) + body


def acknowledge() -> bytes:
    body = u32(0) + u32(65535) + u32(65535) + u32(0) + u32(0)
    return b"ACKF" + u32(len(body) + 8) + body


def tcp_frame(
    payload: bytes,
    *,
    sequence: int,
    acknowledgment: int,
    flags: str,
    originator: bool,
    identifier: int,
) -> object:
    source_ip, destination_ip = (
        (CLIENT_IP, SERVER_IP) if originator else (SERVER_IP, CLIENT_IP)
    )
    source_mac, destination_mac = (
        (CLIENT_MAC, SERVER_MAC) if originator else (SERVER_MAC, CLIENT_MAC)
    )
    source_port, destination_port = (
        (CLIENT_PORT, SERVER_PORT) if originator else (SERVER_PORT, CLIENT_PORT)
    )
    frame = (
        Ether(src=source_mac, dst=destination_mac)
        / IP(src=source_ip, dst=destination_ip, id=identifier, flags="DF")
        / TCP(
            sport=source_port,
            dport=destination_port,
            seq=sequence,
            ack=acknowledgment,
            flags=flags,
            window=65535,
        )
    )
    if payload:
        frame /= Raw(load=payload)
    return frame


def build_packets() -> list[object]:
    client_sequence = 1000
    server_sequence = 5000
    packets = [
        tcp_frame(
            b"",
            sequence=client_sequence,
            acknowledgment=0,
            flags="S",
            originator=True,
            identifier=1,
        ),
        tcp_frame(
            b"",
            sequence=server_sequence,
            acknowledgment=client_sequence + 1,
            flags="SA",
            originator=False,
            identifier=2,
        ),
        tcp_frame(
            b"",
            sequence=client_sequence + 1,
            acknowledgment=server_sequence + 1,
            flags="A",
            originator=True,
            identifier=3,
        ),
    ]
    client_sequence += 1
    server_sequence += 1

    client_payload = hello()
    packets.append(
        tcp_frame(
            client_payload,
            sequence=client_sequence,
            acknowledgment=server_sequence,
            flags="PA",
            originator=True,
            identifier=4,
        )
    )
    client_sequence += len(client_payload)

    server_payload = acknowledge()
    packets.append(
        tcp_frame(
            server_payload,
            sequence=server_sequence,
            acknowledgment=client_sequence,
            flags="PA",
            originator=False,
            identifier=5,
        )
    )
    server_sequence += len(server_payload)

    invalid_chunk = b"MSGF" + u32(4)
    packets.append(
        tcp_frame(
            invalid_chunk,
            sequence=client_sequence,
            acknowledgment=server_sequence,
            flags="PA",
            originator=True,
            identifier=6,
        )
    )
    client_sequence += len(invalid_chunk)

    packets.extend(
        [
            tcp_frame(
                b"",
                sequence=client_sequence,
                acknowledgment=server_sequence,
                flags="FA",
                originator=True,
                identifier=7,
            ),
            tcp_frame(
                b"",
                sequence=server_sequence,
                acknowledgment=client_sequence + 1,
                flags="FA",
                originator=False,
                identifier=8,
            ),
            tcp_frame(
                b"",
                sequence=client_sequence + 1,
                acknowledgment=server_sequence + 1,
                flags="A",
                originator=True,
                identifier=9,
            ),
        ]
    )
    return packets


def main():
    packets = build_packets()
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
