# @TEST-DOC: Reject an OPC UA message chunk whose declared size is smaller than the fixed header, without crashing or parsing further data.
#
# @TEST-EXEC: zeek -b -r $TRACES/opcua/opcua-invalid-chunk-size.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m opcua.log
# @TEST-EXEC: btest-diff-cut -m uid analyzer_name failure_reason analyzer.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/opcua
@load frameworks/analyzer/debug-logging
