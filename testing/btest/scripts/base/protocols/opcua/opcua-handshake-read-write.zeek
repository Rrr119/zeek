# @TEST-DOC: OPC UA binary handshake, secure channel, session, read/write, and publish messages, including TCP segmentation and message chunking.
#
# @TEST-EXEC: zeek -b -r $TRACES/opcua/opcua-handshake-read-write.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m opcua.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/opcua
