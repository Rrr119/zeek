# @TEST-DOC: Verify that DPD detects AMQP from the protocol header without a registered port.
#
# @TEST-EXEC: zeek -b -r $TRACES/amqp/amqp-basic-flow.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/amqp
@load base/protocols/conn

redef AMQP::ports = set();
