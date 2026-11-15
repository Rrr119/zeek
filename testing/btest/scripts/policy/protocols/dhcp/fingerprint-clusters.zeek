# @TEST-DOC: Verify clients are grouped into clusters by their option 55
# @TEST-DOC: fingerprint and logged to dhcp_fp_cluster.log.
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp-fingerprints.pcap %INPUT
# @TEST-EXEC: btest-diff dhcp.log
# @TEST-EXEC: btest-diff dhcp_fp_cluster.log

@load base/protocols/conn
@load protocols/dhcp/fingerprint-clusters
