# @TEST-DOC: Verify option 55 parameter request list, option 60 vendor class,
# @TEST-DOC: and the derived DHCP fingerprint are logged in dhcp.log.
#
# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp-fingerprints.pcap %INPUT
# @TEST-EXEC: btest-diff dhcp.log

@load base/protocols/conn
@load base/protocols/dhcp
