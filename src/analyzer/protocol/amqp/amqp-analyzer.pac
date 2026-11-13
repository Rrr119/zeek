refine flow AMQP_Flow += {
	function proc_protocol_header(msg: AMQP_ProtocolHeader): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_protocol_header )
			zeek::BifEvent::enqueue_amqp_protocol_header(connection()->zeek_analyzer(),
			                                            connection()->zeek_analyzer()->Conn(),
			                                            0, 0, 9, ${msg.revision});
		return true;
		%}

	function proc_connection_start(msg: AMQP_ConnectionStart): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_connection_start )
			zeek::BifEvent::enqueue_amqp_connection_start(connection()->zeek_analyzer(),
			                                             connection()->zeek_analyzer()->Conn(),
			                                             ${msg.version_major}, ${msg.version_minor},
			                                             to_stringval(${msg.mechanisms.value}),
			                                             to_stringval(${msg.locales.value}));
		return true;
		%}

	function proc_connection_start_ok(msg: AMQP_ConnectionStartOk): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_connection_tune(msg: AMQP_ConnectionTune): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_connection_tune )
			zeek::BifEvent::enqueue_amqp_connection_tune(connection()->zeek_analyzer(),
			                                            connection()->zeek_analyzer()->Conn(),
			                                            ${msg.is_orig}, ${msg.channel},
			                                            ${msg.channel_max}, ${msg.frame_max},
			                                            ${msg.heartbeat});
		return true;
		%}

	function proc_connection_open(msg: AMQP_ConnectionOpen): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_connection_open )
			zeek::BifEvent::enqueue_amqp_connection_open(connection()->zeek_analyzer(),
			                                           connection()->zeek_analyzer()->Conn(),
			                                           to_stringval(${msg.virtual_host.value}));
		return true;
		%}

	function proc_connection_open_ok(msg: AMQP_ConnectionOpenOk): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_channel_open(msg: AMQP_ChannelOpen): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_channel_open )
			zeek::BifEvent::enqueue_amqp_channel_open(connection()->zeek_analyzer(),
			                                         connection()->zeek_analyzer()->Conn(),
			                                         ${msg.is_orig}, ${msg.channel});
		return true;
		%}

	function proc_exchange_declare(msg: AMQP_ExchangeDeclare): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_exchange_declare )
			zeek::BifEvent::enqueue_amqp_exchange_declare(connection()->zeek_analyzer(),
			                                             connection()->zeek_analyzer()->Conn(),
			                                             ${msg.channel},
			                                             to_stringval(${msg.exchange.value}),
			                                             to_stringval(${msg.exchange_type.value}));
		return true;
		%}

	function proc_exchange_declare_ok(msg: AMQP_ExchangeDeclareOk): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_queue_declare(msg: AMQP_QueueDeclare): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_queue_declare )
			zeek::BifEvent::enqueue_amqp_queue_declare(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${msg.channel},
			                                          to_stringval(${msg.queue.value}));
		return true;
		%}

	function proc_queue_declare_ok(msg: AMQP_QueueDeclareOk): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_basic_publish(msg: AMQP_BasicPublish): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_basic_publish )
			zeek::BifEvent::enqueue_amqp_basic_publish(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${msg.is_orig}, ${msg.channel},
			                                          to_stringval(${msg.exchange.value}),
			                                          to_stringval(${msg.routing_key.value}),
			                                          (${msg.bits} & 0x01) != 0,
			                                          (${msg.bits} & 0x02) != 0);
		return true;
		%}

	function proc_basic_deliver(msg: AMQP_BasicDeliver): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_basic_deliver )
			zeek::BifEvent::enqueue_amqp_basic_deliver(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${msg.is_orig}, ${msg.channel},
			                                          to_stringval(${msg.consumer_tag.value}),
			                                          ${msg.delivery_tag},
			                                          to_stringval(${msg.exchange.value}),
			                                          to_stringval(${msg.routing_key.value}),
			                                          (${msg.bits} & 0x01) != 0);
		return true;
		%}

	function proc_basic_consume(msg: AMQP_BasicConsume): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_basic_consume )
			zeek::BifEvent::enqueue_amqp_basic_consume(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${msg.channel},
			                                          to_stringval(${msg.queue.value}),
			                                          to_stringval(${msg.consumer_tag.value}));
		return true;
		%}

	function proc_basic_consume_ok(msg: AMQP_BasicConsumeOk): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_content_header(msg: AMQP_ContentHeaderPayload): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_content_header )
			zeek::BifEvent::enqueue_amqp_content_header(connection()->zeek_analyzer(),
			                                           connection()->zeek_analyzer()->Conn(),
			                                           ${msg.channel}, ${msg.class_id},
			                                           ${msg.body_size});
		return true;
		%}

	function proc_content_body(msg: AMQP_ContentBodyFrame): bool
		%{
		if ( amqp_content_body )
			zeek::BifEvent::enqueue_amqp_content_body(connection()->zeek_analyzer(),
			                                        connection()->zeek_analyzer()->Conn(),
			                                        ${msg.channel}, ${msg.payload_size});
		return true;
		%}

	function proc_heartbeat(msg: AMQP_HeartbeatFrame): bool
		%{
		if ( ${msg.channel} != 0 || ${msg.payload_size} != 0 )
			throw Exception("invalid AMQP heartbeat frame");

		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( amqp_heartbeat )
			zeek::BifEvent::enqueue_amqp_heartbeat(connection()->zeek_analyzer(),
			                                     connection()->zeek_analyzer()->Conn());
		return true;
		%}

	function proc_invalid_frame(): bool
		%{
		throw Exception("invalid AMQP frame type");
		return false;
		%}
};

refine typeattr AMQP_ProtocolHeader += &let {
	proc: bool = $context.flow.proc_protocol_header(this);
};

refine typeattr AMQP_ConnectionStart += &let {
	proc: bool = $context.flow.proc_connection_start(this);
};

refine typeattr AMQP_ConnectionStartOk += &let {
	proc: bool = $context.flow.proc_connection_start_ok(this);
};

refine typeattr AMQP_ConnectionTune += &let {
	proc: bool = $context.flow.proc_connection_tune(this);
};

refine typeattr AMQP_ConnectionOpen += &let {
	proc: bool = $context.flow.proc_connection_open(this);
};

refine typeattr AMQP_ConnectionOpenOk += &let {
	proc: bool = $context.flow.proc_connection_open_ok(this);
};

refine typeattr AMQP_ChannelOpen += &let {
	proc: bool = $context.flow.proc_channel_open(this);
};

refine typeattr AMQP_ExchangeDeclare += &let {
	proc: bool = $context.flow.proc_exchange_declare(this);
};

refine typeattr AMQP_ExchangeDeclareOk += &let {
	proc: bool = $context.flow.proc_exchange_declare_ok(this);
};

refine typeattr AMQP_QueueDeclare += &let {
	proc: bool = $context.flow.proc_queue_declare(this);
};

refine typeattr AMQP_QueueDeclareOk += &let {
	proc: bool = $context.flow.proc_queue_declare_ok(this);
};

refine typeattr AMQP_BasicPublish += &let {
	proc: bool = $context.flow.proc_basic_publish(this);
};

refine typeattr AMQP_BasicDeliver += &let {
	proc: bool = $context.flow.proc_basic_deliver(this);
};

refine typeattr AMQP_BasicConsume += &let {
	proc: bool = $context.flow.proc_basic_consume(this);
};

refine typeattr AMQP_BasicConsumeOk += &let {
	proc: bool = $context.flow.proc_basic_consume_ok(this);
};

refine typeattr AMQP_ContentHeaderPayload += &let {
	proc: bool = $context.flow.proc_content_header(this);
};

refine typeattr AMQP_ContentBodyFrame += &let {
	proc: bool = $context.flow.proc_content_body(this);
};

refine typeattr AMQP_HeartbeatFrame += &let {
	proc: bool = $context.flow.proc_heartbeat(this);
};

refine typeattr AMQP_InvalidFrameBody += &let {
	proc: bool = $context.flow.proc_invalid_frame();
};
