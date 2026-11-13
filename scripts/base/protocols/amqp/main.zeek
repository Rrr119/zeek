##! Implements base functionality for AMQP 0-9-1 analysis.
##!
##! AMQP over TLS (normally port 5671/tcp) is first parsed by the SSL
##! analyzer. Once TLS decryption is available, DPD detects the AMQP
##! protocol header in the decrypted stream and activates this analyzer.

@load base/protocols/ssl

module AMQP;

export {
	redef enum Log::ID += {
		CONN_LOG,
		EXCHANGE_LOG,
		QUEUE_LOG,
		PUBLISH_LOG,
	};

	## Well-known plaintext AMQP ports.
	const ports: set[port] = { 5672/tcp } &redef;

	## Well-known TLS ports for AMQP. These are handled by the SSL analyzer
	## and AMQP is detected inside the decrypted stream via DPD.
	const tls_ports: set[port] = { 5671/tcp } &redef;

	global log_policy_conn: Log::PolicyHook;
	global log_policy_exchange: Log::PolicyHook;
	global log_policy_queue: Log::PolicyHook;
	global log_policy_publish: Log::PolicyHook;

	## Connection-level information gathered from the AMQP handshake.
	type ConnInfo: record {
		## Timestamp for when the connection information was first seen.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## AMQP protocol version.
		version: string &log &optional;
		## Virtual host selected by the client.
		vhost: string &log &optional;
		## Negotiated maximum channel number.
		channel_max: count &log &optional;
		## Negotiated maximum frame size.
		frame_max: count &log &optional;
		## Negotiated heartbeat interval.
		heartbeat: count &log &optional;
		## Internal flag preventing duplicate connection log records.
		logged: bool &default=F;
	};

	## Information about a declared exchange.
	type ExchangeInfo: record {
		## Timestamp for when the exchange was declared.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## AMQP channel used for the declaration.
		channel: count &log;
		## Exchange name.
		exchange: string &log;
		## Exchange type such as direct, fanout, headers, or topic.
		exchange_type: string &log;
	};

	## Information about a declared queue.
	type QueueInfo: record {
		## Timestamp for when the queue was declared.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## AMQP channel used for the declaration.
		channel: count &log;
		## Queue name.
		queue: string &log;
	};

	## Information about a published or delivered message.
	type PublishInfo: record {
		## Timestamp for when the message metadata was observed.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## AMQP channel used for the message.
		channel: count &log;
		## Source or destination exchange.
		exchange: string &log;
		## Routing key.
		routing_key: string &log;
		## Total message body size from the content header.
		message_length: count &log;
		## True for basic.publish from the originator, false for delivery.
		from_client: bool &log;
		## Whether the mandatory publish flag was set.
		mandatory: bool &log &default=F;
		## Whether the immediate publish flag was set.
		immediate: bool &log &default=F;
		## Consumer tag for basic.deliver messages.
		consumer_tag: string &log &optional;
		## Delivery tag for basic.deliver messages.
		delivery_tag: count &log &optional;
	};

	type PendingPublish: record {
		exchange: string;
		routing_key: string;
		from_client: bool;
		mandatory: bool &default=F;
		immediate: bool &default=F;
		consumer_tag: string &default="";
		delivery_tag: count &default=0;
	};

	type State: record {
		## Content headers immediately follow the method frame on the same
		## channel, so remember the method metadata until they arrive.
		pending: table[count] of PendingPublish;
	};

	## Event that can be handled to access the AMQP connection record as it
	## is sent to the logging framework.
	global log_amqp_conn: event(rec: ConnInfo);

	## Event that can be handled to access an exchange declaration before it
	## is logged.
	global log_amqp_exchange: event(rec: ExchangeInfo);

	## Event that can be handled to access a queue declaration before it is
	## logged.
	global log_amqp_queue: event(rec: QueueInfo);

	## Event that can be handled to access a publish or delivery before it is
	## logged.
	global log_amqp_publish: event(rec: PublishInfo);
}

# Port 5671 is AMQP over TLS. The SSL analyzer decrypts it and feeds the
# plaintext stream into DPD, which then activates the AMQP analyzer.
redef SSL::ssl_ports += { 5671/tcp };

redef record connection += {
	amqp_conn: ConnInfo &optional;
	amqp_state: State &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(AMQP::CONN_LOG,
	                  Log::Stream($columns=ConnInfo, $ev=log_amqp_conn,
	                              $path="amqp_conn", $policy=log_policy_conn));
	Log::create_stream(AMQP::EXCHANGE_LOG,
	                  Log::Stream($columns=ExchangeInfo, $ev=log_amqp_exchange,
	                              $path="amqp_exchange", $policy=log_policy_exchange));
	Log::create_stream(AMQP::QUEUE_LOG,
	                  Log::Stream($columns=QueueInfo, $ev=log_amqp_queue,
	                              $path="amqp_queue", $policy=log_policy_queue));
	Log::create_stream(AMQP::PUBLISH_LOG,
	                  Log::Stream($columns=PublishInfo, $ev=log_amqp_publish,
	                              $path="amqp_publish", $policy=log_policy_publish));

	Analyzer::register_for_ports(Analyzer::ANALYZER_AMQP, ports);
	}

function set_session(c: connection): ConnInfo
	{
	if ( ! c?$amqp_conn )
		c$amqp_conn = ConnInfo($ts=network_time(), $uid=c$uid, $id=c$id);

	if ( ! c?$amqp_state )
		c$amqp_state = State($pending=table());

	return c$amqp_conn;
	}

event amqp_protocol_header(c: connection, protocol_id: count, major: count,
                           minor: count, revision: count)
	{
	local info = set_session(c);
	info$version = fmt("%d-%d-%d", major, minor, revision);
	}

event amqp_connection_start(c: connection, version_major: count,
                            version_minor: count, mechanisms: string,
                            locales: string)
	{
	set_session(c);
	}

event amqp_connection_tune(c: connection, is_orig: bool, channel: count,
                           channel_max: count, frame_max: count,
                           heartbeat: count)
	{
	local info = set_session(c);
	info$channel_max = channel_max;
	info$frame_max = frame_max;
	info$heartbeat = heartbeat;
	}

event amqp_connection_open(c: connection, vhost: string)
	{
	local info = set_session(c);
	info$vhost = vhost;

	if ( ! info$logged )
		{
		Log::write(AMQP::CONN_LOG, info);
		info$logged = T;
		}
	}

event amqp_exchange_declare(c: connection, channel: count, exchange: string,
                            exchange_type: string)
	{
	Log::write(AMQP::EXCHANGE_LOG,
	           ExchangeInfo($ts=network_time(), $uid=c$uid, $id=c$id,
	                        $channel=channel, $exchange=exchange,
	                        $exchange_type=exchange_type));
	}

event amqp_queue_declare(c: connection, channel: count, queue: string)
	{
	Log::write(AMQP::QUEUE_LOG,
	           QueueInfo($ts=network_time(), $uid=c$uid, $id=c$id,
	                     $channel=channel, $queue=queue));
	}

event amqp_basic_publish(c: connection, is_orig: bool, channel: count,
                         exchange: string, routing_key: string,
                         mandatory: bool, immediate: bool)
	{
	set_session(c);
	c$amqp_state$pending[channel] =
	    PendingPublish($exchange=exchange, $routing_key=routing_key,
	                   $from_client=is_orig, $mandatory=mandatory,
	                   $immediate=immediate);
	}

event amqp_basic_deliver(c: connection, is_orig: bool, channel: count,
                         consumer_tag: string, delivery_tag: count,
                         exchange: string, routing_key: string,
                         redelivered: bool)
	{
	set_session(c);
	c$amqp_state$pending[channel] =
	    PendingPublish($exchange=exchange, $routing_key=routing_key,
	                   $from_client=is_orig, $consumer_tag=consumer_tag,
	                   $delivery_tag=delivery_tag);
	}

event amqp_content_header(c: connection, channel: count, class_id: count,
                          body_size: count)
	{
	if ( ! c?$amqp_state || channel !in c$amqp_state$pending || class_id != 60 )
		return;

	local pending = c$amqp_state$pending[channel];
	delete c$amqp_state$pending[channel];

	Log::write(AMQP::PUBLISH_LOG,
	           PublishInfo($ts=network_time(), $uid=c$uid, $id=c$id,
	                       $channel=channel, $exchange=pending$exchange,
	                       $routing_key=pending$routing_key,
	                       $message_length=body_size,
	                       $from_client=pending$from_client,
	                       $mandatory=pending$mandatory,
	                       $immediate=pending$immediate,
	                       $consumer_tag=pending$consumer_tag,
	                       $delivery_tag=pending$delivery_tag));
	}
