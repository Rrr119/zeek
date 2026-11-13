# @TEST-DOC: Verify AMQP 0-9-1 parsing, events, connection/exchange/queue/publish logs, and service detection.
#
# @TEST-EXEC: zeek -b -r $TRACES/amqp/amqp-basic-flow.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff amqp_conn.log
# @TEST-EXEC: btest-diff amqp_exchange.log
# @TEST-EXEC: btest-diff amqp_queue.log
# @TEST-EXEC: btest-diff amqp_publish.log

@load base/protocols/amqp
@load base/protocols/conn
