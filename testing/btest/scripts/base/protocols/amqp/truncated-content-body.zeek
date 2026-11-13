# @TEST-DOC: Verify that a truncated AMQP content body does not crash Zeek.
#
# @TEST-EXEC: zeek -b -r $TRACES/amqp/amqp-truncated-content-body.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff amqp_publish.log

@load base/protocols/amqp
@load base/protocols/conn
