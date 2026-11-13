# @TEST-DOC: JA4QUIC is generated from QUIC Initial packet ClientHello data.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -C -r $TRACES/quic/quicv2-http3-443.pcap %INPUT
# @TEST-EXEC: test "$(zeek-cut kind < ja4.log | grep -c '^JA4QUIC$')" -ge 1
# @TEST-EXEC: btest-diff-cut -m uid kind fingerprint prefix raw ja4.log

@load base/frameworks/ja4
