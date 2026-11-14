#!/usr/bin/env python3
"""Generate an OPC UA binary trace covering handshake and data access.

The trace contains Hello/Acknowledge, OpenSecureChannel, GetEndpoints,
CreateSession, a segmented Read request, a chunked Write request with a
non-Good operation status, CreateSubscription, Publish, and
CloseSecureChannel. The complete TCP lifecycle is included.

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
BASE_TIME = 1_700_000_000.0

SECURITY_POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
ENDPOINT_URL = f"opc.tcp://{SERVER_IP}:{SERVER_PORT}"
TRANSPORT_PROFILE = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"


def u8(value: int) -> bytes:
    return value.to_bytes(1, "little")


def u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def f64(value: float) -> bytes:
    import struct

    return struct.pack("<d", value)


def opcua_string(value: str | None) -> bytes:
    if value is None:
        return i32(-1)
    encoded = value.encode()
    return i32(len(encoded)) + encoded


def opcua_bytes(value: bytes | None) -> bytes:
    if value is None:
        return i32(-1)
    return i32(len(value)) + value


def string_array(values: list[str]) -> bytes:
    return u32(len(values)) + b"".join(opcua_string(value) for value in values)


def node_id(identifier: int, namespace: int = 0) -> bytes:
    if namespace == 0 and identifier <= 0xFF:
        return u8(0x00) + u8(identifier)
    if namespace <= 0xFF and identifier <= 0xFFFF:
        return u8(0x01) + u8(namespace) + u16(identifier)
    return u8(0x02) + u16(namespace) + u32(identifier)


def null_node_id() -> bytes:
    return node_id(0)


def null_extension_object() -> bytes:
    return null_node_id() + u8(0)


def extension_object(type_id: int, body: bytes) -> bytes:
    return node_id(type_id) + u8(1) + i32(len(body)) + body


def request_header(request_handle: int, token: bytes | None = None) -> bytes:
    return (
        (token if token is not None else null_node_id())
        + u64(0)
        + u32(request_handle)
        + u32(0)
        + opcua_string(None)
        + u32(0)
        + null_extension_object()
    )


def response_header(request_handle: int, status: int = 0) -> bytes:
    return (
        u64(0)
        + u32(request_handle)
        + u32(status)
        + u8(0)
        + u32(0)
        + null_extension_object()
    )


def application_description() -> bytes:
    return (
        opcua_string("urn:example:audit-server")
        + opcua_string("urn:example:product")
        + u8(0)
        + u32(0)
        + opcua_string(None)
        + opcua_string(None)
        + u32(0)
    )


def endpoint_description() -> bytes:
    return (
        opcua_string(ENDPOINT_URL)
        + application_description()
        + opcua_bytes(None)
        + u32(1)
        + opcua_string(SECURITY_POLICY_NONE)
        + u32(0)
        + opcua_string(TRANSPORT_PROFILE)
        + u8(0)
    )


def hello() -> bytes:
    body = (
        u32(0) + u32(65535) + u32(65535) + u32(0) + u32(0) + opcua_string(ENDPOINT_URL)
    )
    return b"HELF" + u32(len(body) + 8) + body


def acknowledge() -> bytes:
    body = u32(0) + u32(65535) + u32(65535) + u32(0) + u32(0)
    return b"ACKF" + u32(len(body) + 8) + body


def secure_chunk(
    message_type: bytes,
    chunk_type: bytes,
    payload: bytes,
    *,
    sequence: int,
    request_id: int,
    channel_id: int = 1,
    policy: str = SECURITY_POLICY_NONE,
) -> bytes:
    body = (
        u32(channel_id)
        + opcua_string(policy)
        + opcua_bytes(None)
        + opcua_bytes(None)
        + u32(sequence)
        + u32(request_id)
        + payload
    )
    return message_type + chunk_type + u32(len(body) + 8) + body


def service(encoding_id: int, body: bytes) -> bytes:
    return node_id(encoding_id) + body


def get_variant_boolean(value: bool) -> bytes:
    return u8(1) + u8(int(value))


def build_messages() -> list[tuple[bool, bytes]]:
    """Return (originator, payload) pairs in wire order."""
    token = node_id(2000, namespace=1)
    read_node = node_id(1001, namespace=2)
    write_node = node_id(1002, namespace=2)

    open_request_body = (
        request_header(1)
        + u32(0)
        + u32(0)
        + u32(1)
        + opcua_bytes(None)
        + u32(3_600_000)
    )
    open_response_body = (
        response_header(1)
        + u32(0)
        + u32(1)
        + u32(1)
        + u64(0)
        + u32(3_600_000)
        + opcua_bytes(None)
    )

    get_endpoints_request_body = (
        request_header(2)
        + opcua_string(ENDPOINT_URL)
        + string_array([])
        + string_array([])
    )
    get_endpoints_response_body = response_header(2) + u32(1) + endpoint_description()

    create_session_request_body = (
        request_header(3)
        + application_description()
        + opcua_string(None)
        + opcua_string(ENDPOINT_URL)
        + opcua_string("zeek-audit")
        + opcua_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        + opcua_bytes(None)
        + f64(600_000)
        + u32(0)
    )
    create_session_response_body = (
        response_header(3)
        + node_id(1000, namespace=1)
        + token
        + f64(600_000)
        + opcua_bytes(b"\x10\x20\x30\x40")
        + opcua_bytes(None)
        + u32(0)
        + u32(0)
        + opcua_string(None)
        + opcua_bytes(None)
        + u32(0)
    )

    read_request_body = (
        request_header(4, token)
        + f64(0)
        + u32(0)
        + u32(1)
        + read_node
        + u32(13)
        + opcua_string(None)
        + u16(0)
        + opcua_string(None)
    )
    read_response_body = (
        response_header(4) + u32(1) + u8(0x03) + get_variant_boolean(True) + u32(0)
    )

    write_request_body = (
        request_header(5, token)
        + u32(1)
        + write_node
        + u32(13)
        + opcua_string(None)
        + u8(0x01)
        + get_variant_boolean(False)
    )
    write_response_body = response_header(5) + u32(1) + u32(0x80350000)

    create_subscription_request_body = (
        request_header(6, token)
        + f64(1_000)
        + u32(10)
        + u32(3)
        + u32(0)
        + u8(1)
        + u8(0)
    )
    create_subscription_response_body = (
        response_header(6) + u32(42) + f64(1_000) + u32(10) + u32(3)
    )

    publish_request_body = request_header(7, token) + u32(1) + u32(42) + u32(1)
    notification = extension_object(811, b"")
    publish_response_body = (
        response_header(7)
        + u32(42)
        + u32(1)
        + u32(1)
        + u8(0)
        + u32(1)
        + u64(0)
        + u32(1)
        + notification
        + u32(1)
        + u32(0)
        + u32(0)
    )

    close_request_body = request_header(8, token)

    open_request = secure_chunk(
        b"OPN",
        b"F",
        service(446, open_request_body),
        sequence=1,
        request_id=1,
        channel_id=0,
    )
    open_response = secure_chunk(
        b"OPN",
        b"F",
        service(449, open_response_body),
        sequence=2,
        request_id=1,
    )

    write_payload = service(673, write_request_body)
    write_chunk_split = len(write_payload) // 2
    write_chunk_one = secure_chunk(
        b"MSG",
        b"C",
        write_payload[:write_chunk_split],
        sequence=6,
        request_id=5,
    )
    write_chunk_two = secure_chunk(
        b"MSG",
        b"F",
        write_payload[write_chunk_split:],
        sequence=7,
        request_id=5,
    )

    return [
        (True, hello()),
        (False, acknowledge()),
        (True, open_request),
        (False, open_response),
        (
            True,
            secure_chunk(
                b"MSG",
                b"F",
                service(428, get_endpoints_request_body),
                sequence=3,
                request_id=2,
            ),
        ),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(431, get_endpoints_response_body),
                sequence=4,
                request_id=2,
            ),
        ),
        (
            True,
            secure_chunk(
                b"MSG",
                b"F",
                service(461, create_session_request_body),
                sequence=5,
                request_id=3,
            ),
        ),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(464, create_session_response_body),
                sequence=6,
                request_id=3,
            ),
        ),
        (
            True,
            secure_chunk(
                b"MSG",
                b"F",
                service(631, read_request_body),
                sequence=8,
                request_id=4,
            ),
        ),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(634, read_response_body),
                sequence=9,
                request_id=4,
            ),
        ),
        (True, write_chunk_one),
        (True, write_chunk_two),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(676, write_response_body),
                sequence=10,
                request_id=5,
            ),
        ),
        (
            True,
            secure_chunk(
                b"MSG",
                b"F",
                service(787, create_subscription_request_body),
                sequence=11,
                request_id=6,
            ),
        ),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(790, create_subscription_response_body),
                sequence=12,
                request_id=6,
            ),
        ),
        (
            True,
            secure_chunk(
                b"MSG",
                b"F",
                service(826, publish_request_body),
                sequence=13,
                request_id=7,
            ),
        ),
        (
            False,
            secure_chunk(
                b"MSG",
                b"F",
                service(829, publish_response_body),
                sequence=14,
                request_id=7,
            ),
        ),
        (
            True,
            secure_chunk(
                b"CLO",
                b"F",
                service(452, close_request_body),
                sequence=15,
                request_id=8,
            ),
        ),
    ]


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
    packets = []
    client_sequence = 1000
    server_sequence = 5000
    identifier = 1

    packets.extend(
        [
            tcp_frame(
                b"",
                sequence=client_sequence,
                acknowledgment=0,
                flags="S",
                originator=True,
                identifier=identifier,
            ),
            tcp_frame(
                b"",
                sequence=server_sequence,
                acknowledgment=client_sequence + 1,
                flags="SA",
                originator=False,
                identifier=identifier + 1,
            ),
            tcp_frame(
                b"",
                sequence=client_sequence + 1,
                acknowledgment=server_sequence + 1,
                flags="A",
                originator=True,
                identifier=identifier + 2,
            ),
        ]
    )
    client_sequence += 1
    server_sequence += 1
    identifier += 3

    for originator, payload in build_messages():
        segments = [payload]
        if payload.startswith(b"MSG") and b"\x01\x00\x77\x02" in payload:
            # Split the Read request across TCP segments. OPC UA TCP
            # reassembly must reconstruct it before service decoding.
            split = max(16, len(payload) // 2)
            segments = [payload[:split], payload[split:]]

        for segment in segments:
            if originator:
                sequence = client_sequence
                acknowledgment = server_sequence
                client_sequence += len(segment)
            else:
                sequence = server_sequence
                acknowledgment = client_sequence
                server_sequence += len(segment)

            packets.append(
                tcp_frame(
                    segment,
                    sequence=sequence,
                    acknowledgment=acknowledgment,
                    flags="PA",
                    originator=originator,
                    identifier=identifier,
                )
            )
            identifier += 1

    packets.extend(
        [
            tcp_frame(
                b"",
                sequence=client_sequence,
                acknowledgment=server_sequence,
                flags="FA",
                originator=True,
                identifier=identifier,
            ),
            tcp_frame(
                b"",
                sequence=server_sequence,
                acknowledgment=client_sequence + 1,
                flags="FA",
                originator=False,
                identifier=identifier + 1,
            ),
            tcp_frame(
                b"",
                sequence=client_sequence + 1,
                acknowledgment=server_sequence + 1,
                flags="A",
                originator=True,
                identifier=identifier + 2,
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
