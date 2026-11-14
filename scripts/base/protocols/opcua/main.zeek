##! OPC UA binary protocol analysis.
##!
##! See :doc:`/reference/logs/opcua` for supported services and limitations.

@load ./consts

module OPCUA;

export {
	redef enum Log::ID += { LOG };

	## Policy hook for :file:`opcua.log`.
	global log_policy: Log::PolicyHook;

	## A parsed OPC UA transport message or reassembled service message.
	type Info: record {
		## Timestamp when the message was observed.
		ts: time &log;
		## Unique identifier for the connection.
		uid: string &log;
		## Connection tuple.
		id: conn_id &log;
		## True for messages sent by the TCP originator.
		is_orig: bool &log;
		## OPC UA transport message type (HEL, ACK, OPN, MSG, CLO, ABO).
		message_type: string &log;
		## Parsed service name.
		service: string &log;
		## Most recently observed endpoint URL.
		endpoint: string &log &optional;
		## Most recently observed security policy URI.
		security_policy: string &log &optional;
		## Most recently observed message security mode.
		security_mode: string &log &optional;
		## StatusCode value, if the message carries one.
		status: count &log &optional;
		## Symbolic name for :zeek:field:`Info:status`.
		status_code: string &log &optional;
		## NodeId of the most recently observed session.
		session_id: string &log &optional;
		## Most recently observed subscription identifier.
		subscription_id: count &log &optional;
		## Secure-channel request identifier.
		request_id: count &log &optional;
		## C for a continuation chunk, F for a final chunk.
		chunk_type: string &log;
		## Number of transport chunks used by the message.
		chunk_count: count &log;
		## Size of the final transport chunk in bytes.
		message_size: count &log;
		## NodeIds extracted from a service request.
		node_ids: set[string] &log &optional;
		## ExtensionObject type NodeIds observed in the message.
		extension_objects: set[string] &log &optional;
	};

	## Event for access to a record before it is written to
	## :file:`opcua.log`.
	global log_opcua: event(rec: Info);

	## Maps a StatusCode value to its symbolic name.
	global status_code_name: function(status: count): string;
}

event zeek_init() &priority=5 {
	Log::create_stream(OPCUA::LOG,
	                   Log::Stream($columns=Info, $ev=log_opcua, $path="opcua",
	                               $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPCUA, ports);
}

event opcua_message(c: connection, is_orig: bool, message_type: string,
                    service: string, endpoint: string, security_policy: string,
                    security_mode: string, status: count, has_status: bool,
                    session_id: string, subscription_id: count,
                    has_subscription: bool, request_id: count,
                    chunk_type: string, chunk_count: count,
                    message_size: count, node_ids: string_vec,
                    extension_objects: string_vec) {
	local info = Info($ts=network_time(), $uid=c$uid, $id=c$id,
	                  $is_orig=is_orig, $message_type=message_type,
	                  $service=service, $chunk_type=chunk_type,
	                  $chunk_count=chunk_count,
	                  $message_size=message_size);

	if ( endpoint != "" )
		info$endpoint = endpoint;
	if ( security_policy != "" )
		info$security_policy = security_policy;
	if ( security_mode != "" )
		info$security_mode = security_mode;
	if ( has_status ) {
		info$status = status;
		info$status_code = status_code_name(status);
	}
	if ( session_id != "" )
		info$session_id = session_id;
	if ( has_subscription )
		info$subscription_id = subscription_id;
	info$request_id = request_id;

	if ( |node_ids| > 0 ) {
		info$node_ids = set();
		for ( idx in node_ids )
			add info$node_ids[node_ids[idx]];
	}
	if ( |extension_objects| > 0 ) {
		info$extension_objects = set();
		for ( idx in extension_objects )
			add info$extension_objects[extension_objects[idx]];
	}

	Log::write(OPCUA::LOG, info);
}

function status_code_name(status: count): string {
	local names = {
		[0x00000000] = "Good",
		[0x40000000] = "Uncertain",
		[0x80000000] = "Bad",
		[0x80010000] = "BadUnexpectedError",
		[0x80020000] = "BadInternalError",
		[0x80030000] = "BadOutOfMemory",
		[0x80040000] = "BadResourceUnavailable",
		[0x80050000] = "BadCommunicationError",
		[0x80060000] = "BadEncodingError",
		[0x80070000] = "BadDecodingError",
		[0x80080000] = "BadEncodingLimitsExceeded",
		[0x80090000] = "BadUnknownResponse",
		[0x800A0000] = "BadTimeout",
		[0x800B0000] = "BadServiceUnsupported",
		[0x800C0000] = "BadShutdown",
		[0x800D0000] = "BadServerNotConnected",
		[0x800E0000] = "BadServerHalted",
		[0x800F0000] = "BadNothingToDo",
		[0x80100000] = "BadTooManyOperations",
		[0x80110000] = "BadDataTypeIdUnknown",
		[0x80120000] = "BadCertificateInvalid",
		[0x80130000] = "BadSecurityChecksFailed",
		[0x80190000] = "BadIdentityTokenInvalid",
		[0x801A0000] = "BadIdentityTokenRejected",
		[0x801B0000] = "BadSecureChannelIdInvalid",
		[0x801C0000] = "BadInvalidTimestamp",
		[0x801D0000] = "BadNonceInvalid",
		[0x801E0000] = "BadSessionIdInvalid",
		[0x801F0000] = "BadSessionClosed",
		[0x80200000] = "BadSessionNotActivated",
		[0x80210000] = "BadSubscriptionIdInvalid",
		[0x80220000] = "BadRequestHeaderInvalid",
		[0x80230000] = "BadTimestampsToReturnInvalid",
		[0x80240000] = "BadRequestCancelledByClient",
		[0x80250000] = "BadTooManyArguments",
		[0x80290000] = "BadNoSubscription",
		[0x802A0000] = "BadMonitoredItemIdInvalid",
		[0x80300000] = "BadContinuationPointInvalid",
		[0x80310000] = "BadNoContinuationPoints",
		[0x80320000] = "BadReferenceTypeIdInvalid",
		[0x80330000] = "BadBrowseDirectionInvalid",
		[0x80340000] = "BadNodeIdInvalid",
		[0x80350000] = "BadNodeIdUnknown",
		[0x80360000] = "BadAttributeIdInvalid",
		[0x80370000] = "BadIndexRangeInvalid",
		[0x80380000] = "BadIndexRangeNoData",
		[0x803B0000] = "BadNotReadable",
		[0x803C0000] = "BadNotWritable",
		[0x803D0000] = "BadOutOfRange",
		[0x803E0000] = "BadNotSupported",
		[0x803F0000] = "BadNotFound",
		[0x80400000] = "BadObjectDeleted",
		[0x80410000] = "BadNotImplemented",
	};

	if ( status in names )
		return names[status];
	if ( (status & 0xC0000000) == 0x80000000 )
		return fmt("Bad-0x%08X", status);
	if ( (status & 0xC0000000) == 0x40000000 )
		return fmt("Uncertain-0x%08X", status);
	return fmt("0x%08X", status);
}
