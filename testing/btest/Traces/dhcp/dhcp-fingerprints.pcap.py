#!/usr/bin/env python3
"""Generate a DHCP trace exercising option 55/60 fingerprinting and clusters.

The trace contains four DHCPDISCOVER messages from three clients.  Each
message carries a vendor class identifier (option 60) and a parameter request
list (option 55).  The first two clients request the same options in the same
order and therefore share a DHCP fingerprint, while the third client uses two
different parameter request lists of its own.  This lets the fingerprinting
regression test verify both the per-message ``dhcp_fingerprint`` field and the
grouping of clients into fingerprint clusters.

Written with OpenAI Codex using Scapy.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, wrpcap

BASE_TIME = 1_700_000_000.0

# (client MAC, transaction id, parameter request list, vendor class id)
MESSAGES = [
    (
        "02:00:00:00:00:01",
        0x10000001,
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 252],
        "MSFT 5.0",
    ),
    (
        "02:00:00:00:00:02",
        0x10000002,
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 252],
        "MSFT 5.0",
    ),
    (
        "02:00:00:00:00:03",
        0x10000003,
        [1, 3, 6, 15, 119, 252],
        "android-dhcp-13",
    ),
    (
        "02:00:00:00:00:03",
        0x10000004,
        [1, 3, 6, 12, 15, 28, 42],
        "android-dhcp-13",
    ),
]


def dhcp_discover(mac, xid, param_list, vendor_class, ts):
    bootp = BOOTP(
        op=1,
        htype=1,
        hlen=6,
        hops=0,
        xid=xid,
        flags=0x8000,
        chaddr=mac,
    )
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / bootp
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("param_req_list", param_list),
                ("vendor_class_id", vendor_class),
                "end",
            ]
        )
    )
    pkt.time = ts
    return pkt


def main():
    packets = [
        dhcp_discover(mac, xid, param_list, vendor_class, BASE_TIME + index * 0.001)
        for index, (mac, xid, param_list, vendor_class) in enumerate(MESSAGES)
    ]
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
