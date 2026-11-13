# AMQP 0-9-1 wire format.
#
# Reference: https://www.rabbitmq.com/amqp-0-9-1-errata.html and
# https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf

enum AMQP_frame_type {
	AMQP_PROTOCOL_HEADER      = 0x41, # First byte of "AMQP"
	AMQP_METHOD_FRAME         = 0x01,
	AMQP_CONTENT_HEADER_FRAME = 0x02,
	AMQP_CONTENT_BODY_FRAME   = 0x03,
	AMQP_HEARTBEAT_FRAME      = 0x08,
};

enum AMQP_class_id {
	AMQP_CONNECTION_CLASS = 10,
	AMQP_CHANNEL_CLASS    = 20,
	AMQP_EXCHANGE_CLASS   = 40,
	AMQP_QUEUE_CLASS      = 50,
	AMQP_BASIC_CLASS      = 60,
};

enum AMQP_method_id {
	AMQP_CONNECTION_START    = 10,
	AMQP_CONNECTION_START_OK = 11,
	AMQP_CONNECTION_TUNE     = 30,
	AMQP_CONNECTION_TUNE_OK  = 31,
	AMQP_CONNECTION_OPEN     = 40,
	AMQP_CONNECTION_OPEN_OK  = 41,
	AMQP_CONNECTION_CLOSE    = 50,
	AMQP_CONNECTION_CLOSE_OK = 51,

	AMQP_CHANNEL_OPEN        = 10,
	AMQP_CHANNEL_OPEN_OK     = 11,

	AMQP_EXCHANGE_DECLARE    = 10,
	AMQP_EXCHANGE_DECLARE_OK = 11,

	AMQP_QUEUE_DECLARE       = 10,
	AMQP_QUEUE_DECLARE_OK    = 11,

	AMQP_BASIC_CONSUME       = 20,
	AMQP_BASIC_CONSUME_OK    = 21,
	AMQP_BASIC_CANCEL        = 30,
	AMQP_BASIC_CANCEL_OK     = 31,
	AMQP_BASIC_PUBLISH       = 40,
	AMQP_BASIC_DELIVER       = 60,
};

type AMQP_shortstr = record {
	len: uint8;
	value: bytestring &length=len;
};

type AMQP_longstr = record {
	len: uint32;
	value: bytestring &length=len;
} &byteorder=bigendian;

type AMQP_field_table = record {
	len: uint32;
	value: bytestring &length=len &transient;
} &byteorder=bigendian;

type AMQP_PDU(is_orig: bool) = record {
	# These fields are shared by frame headers and the initial protocol
	# header. For protocol headers, channel and payload_size cover the bytes
	# "MQ" and "P\x00\x00\x09" respectively.
	frame_type:   uint8 &enforce(frame_type == AMQP_PROTOCOL_HEADER ||
	                             frame_type == AMQP_METHOD_FRAME ||
	                             frame_type == AMQP_CONTENT_HEADER_FRAME ||
	                             frame_type == AMQP_CONTENT_BODY_FRAME ||
	                             frame_type == AMQP_HEARTBEAT_FRAME);
	channel:      uint16;
	payload_size: uint32 &enforce($context.connection.validate_frame_size(frame_type,
	                                                                    payload_size));
	body: case frame_type of {
		AMQP_PROTOCOL_HEADER      -> protocol_header:      AMQP_ProtocolHeader(channel, payload_size);
		AMQP_METHOD_FRAME         -> method_frame:        AMQP_MethodFrameBody(is_orig, channel, payload_size);
		AMQP_CONTENT_HEADER_FRAME -> content_header_frame: AMQP_ContentHeaderFrame(channel, payload_size);
		AMQP_CONTENT_BODY_FRAME   -> content_body_frame:   AMQP_ContentBodyFrame(channel, payload_size);
		AMQP_HEARTBEAT_FRAME      -> heartbeat_frame:      AMQP_HeartbeatFrame(channel, payload_size);
		default                   -> invalid_frame:        AMQP_InvalidFrameBody(payload_size);
	};
} &length=frame_type == AMQP_PROTOCOL_HEADER ? 8 : payload_size + 8, &byteorder=bigendian;

type AMQP_ProtocolHeader(protocol_signature: uint16, version_prefix: uint32) = record {
	revision: uint8 &enforce(revision == 1);
} &let {
	valid_magic: bool = $context.connection.validate_protocol_header(protocol_signature,
	                                                                version_prefix,
	                                                                revision);
};

type AMQP_MethodFrameBody(is_orig: bool, channel: uint16, payload_size: uint32) = record {
	payload:   AMQP_MethodPayload(is_orig, channel, payload_size) &length=payload_size;
	frame_end: uint8 &enforce(frame_end == 0xce);
};

type AMQP_MethodPayload(is_orig: bool, channel: uint16, payload_size: uint32) = record {
	class_id:  uint16 &enforce(payload_size >= 4);
	method_id: uint16;
	args:      AMQP_MethodArgs(is_orig, channel, class_id, method_id) &length=payload_size-4;
} &byteorder=bigendian;

type AMQP_MethodArgs(is_orig: bool, channel: uint16, class_id: uint16, method_id: uint16) = record {
	args: case class_id of {
		AMQP_CONNECTION_CLASS -> connection_args: AMQP_ConnectionArgs(is_orig, channel, method_id);
		AMQP_CHANNEL_CLASS    -> channel_args:    AMQP_ChannelArgs(is_orig, channel, method_id);
		AMQP_EXCHANGE_CLASS   -> exchange_args:   AMQP_ExchangeArgs(channel, method_id);
		AMQP_QUEUE_CLASS      -> queue_args:      AMQP_QueueArgs(channel, method_id);
		AMQP_BASIC_CLASS      -> basic_args:      AMQP_BasicArgs(is_orig, channel, method_id);
		default               -> unknown_args:    bytestring &restofdata &transient;
	};
};

type AMQP_ConnectionArgs(is_orig: bool, channel: uint16, method_id: uint16) = case method_id of {
	AMQP_CONNECTION_START    -> start:    AMQP_ConnectionStart;
	AMQP_CONNECTION_START_OK -> start_ok: AMQP_ConnectionStartOk;
	AMQP_CONNECTION_TUNE     -> tune:     AMQP_ConnectionTune(is_orig, channel);
	AMQP_CONNECTION_TUNE_OK  -> tune_ok:  AMQP_ConnectionTune(is_orig, channel);
	AMQP_CONNECTION_OPEN     -> open:     AMQP_ConnectionOpen;
	AMQP_CONNECTION_OPEN_OK  -> open_ok:  AMQP_ConnectionOpenOk;
	AMQP_CONNECTION_CLOSE    -> close:    bytestring &restofdata &transient;
	AMQP_CONNECTION_CLOSE_OK -> close_ok: bytestring &restofdata &transient;
	default                  -> unknown:  bytestring &restofdata &transient;
};

type AMQP_ConnectionStart = record {
	version_major:     uint8;
	version_minor:     uint8;
	server_properties: AMQP_field_table;
	mechanisms:        AMQP_longstr;
	locales:           AMQP_longstr;
} &byteorder=bigendian;

type AMQP_ConnectionStartOk = record {
	client_properties: AMQP_field_table;
	mechanism:         AMQP_shortstr;
	response:          AMQP_longstr;
	locale:            AMQP_shortstr;
} &byteorder=bigendian;

type AMQP_ConnectionTune(is_orig: bool, channel: uint16) = record {
	channel_max: uint16;
	frame_max:   uint32;
	heartbeat:   uint16;
} &byteorder=bigendian;

type AMQP_ConnectionOpen = record {
	virtual_host: AMQP_shortstr;
	reserved:     AMQP_shortstr;
	bits:         uint8;
};

type AMQP_ConnectionOpenOk = record {
	reserved: AMQP_shortstr;
};

type AMQP_ChannelArgs(is_orig: bool, channel: uint16, method_id: uint16) = case method_id of {
	AMQP_CHANNEL_OPEN    -> open:    AMQP_ChannelOpen(is_orig, channel);
	AMQP_CHANNEL_OPEN_OK -> open_ok: AMQP_ChannelOpen(is_orig, channel);
	default              -> unknown: bytestring &restofdata &transient;
};

type AMQP_ChannelOpen(is_orig: bool, channel: uint16) = record {
	reserved: AMQP_shortstr;
};

type AMQP_ExchangeArgs(channel: uint16, method_id: uint16) = case method_id of {
	AMQP_EXCHANGE_DECLARE    -> declare:    AMQP_ExchangeDeclare(channel);
	AMQP_EXCHANGE_DECLARE_OK -> declare_ok: AMQP_ExchangeDeclareOk;
	default                  -> unknown:     bytestring &restofdata &transient;
};

type AMQP_ExchangeDeclare(channel: uint16) = record {
	ticket:        uint16;
	exchange:      AMQP_shortstr;
	exchange_type: AMQP_shortstr;
	bits:          uint8;
	arguments:     AMQP_field_table;
} &byteorder=bigendian;

type AMQP_ExchangeDeclareOk = empty;

type AMQP_QueueArgs(channel: uint16, method_id: uint16) = case method_id of {
	AMQP_QUEUE_DECLARE    -> declare:    AMQP_QueueDeclare(channel);
	AMQP_QUEUE_DECLARE_OK -> declare_ok: AMQP_QueueDeclareOk;
	default               -> unknown:    bytestring &restofdata &transient;
};

type AMQP_QueueDeclare(channel: uint16) = record {
	ticket:      uint16;
	queue:       AMQP_shortstr;
	bits:        uint8;
	arguments:   AMQP_field_table;
} &byteorder=bigendian;

type AMQP_QueueDeclareOk = record {
	queue:          AMQP_shortstr;
	message_count:  uint32;
	consumer_count: uint32;
} &byteorder=bigendian;

type AMQP_BasicArgs(is_orig: bool, channel: uint16, method_id: uint16) = case method_id of {
	AMQP_BASIC_CONSUME    -> consume:    AMQP_BasicConsume(channel);
	AMQP_BASIC_CONSUME_OK -> consume_ok: AMQP_BasicConsumeOk;
	AMQP_BASIC_PUBLISH    -> publish:    AMQP_BasicPublish(is_orig, channel);
	AMQP_BASIC_DELIVER    -> deliver:    AMQP_BasicDeliver(is_orig, channel);
	AMQP_BASIC_CANCEL     -> cancel:     bytestring &restofdata &transient;
	AMQP_BASIC_CANCEL_OK  -> cancel_ok:  bytestring &restofdata &transient;
	default               -> unknown:    bytestring &restofdata &transient;
};

type AMQP_BasicPublish(is_orig: bool, channel: uint16) = record {
	ticket:      uint16;
	exchange:    AMQP_shortstr;
	routing_key: AMQP_shortstr;
	bits:        uint8;
} &byteorder=bigendian;

type AMQP_BasicDeliver(is_orig: bool, channel: uint16) = record {
	consumer_tag: AMQP_shortstr;
	delivery_tag: uint64;
	bits:         uint8;
	exchange:     AMQP_shortstr;
	routing_key:  AMQP_shortstr;
} &byteorder=bigendian;

type AMQP_BasicConsume(channel: uint16) = record {
	ticket:       uint16;
	queue:        AMQP_shortstr;
	consumer_tag: AMQP_shortstr;
	bits:         uint8;
	arguments:    AMQP_field_table;
} &byteorder=bigendian;

type AMQP_BasicConsumeOk = record {
	consumer_tag: AMQP_shortstr;
};

type AMQP_ContentHeaderFrame(channel: uint16, payload_size: uint32) = record {
	payload:   AMQP_ContentHeaderPayload(channel, payload_size) &length=payload_size;
	frame_end: uint8 &enforce(frame_end == 0xce);
};

type AMQP_ContentHeaderPayload(channel: uint16, payload_size: uint32) = record {
	class_id:       uint16 &enforce(payload_size >= 14);
	weight:         uint16;
	body_size:      uint64;
	property_flags: uint16;
	properties:     bytestring &restofdata &transient;
} &byteorder=bigendian;

type AMQP_ContentBodyFrame(channel: uint16, payload_size: uint32) = record {
	body:      bytestring &length=payload_size &transient;
	frame_end: uint8 &enforce(frame_end == 0xce);
};

type AMQP_HeartbeatFrame(channel: uint16, payload_size: uint32) = record {
	frame_end: uint8 &enforce(frame_end == 0xce);
};

type AMQP_InvalidFrameBody(payload_size: uint32) = record {
	payload:   bytestring &length=payload_size &transient;
	frame_end: uint8 &enforce(frame_end == 0xce);
};

refine connection AMQP_Conn += {
	function validate_frame_size(frame_type: uint8, size: uint32): bool
		%{
		// The protocol header reuses this field for the literal bytes
		// "P\x00\x00\x09", so only apply the limit to frame payloads.
		if ( frame_type != 0x41 ) {
			if ( size > 0xfffffff7u )
				throw Exception("AMQP frame payload length overflows frame length");

			if ( zeek::BifConst::AMQP::max_frame_size > 0 &&
			     size > zeek::BifConst::AMQP::max_frame_size )
				throw Exception(zeek::util::fmt("AMQP frame payload exceeds limit: %u > %u",
				                                static_cast<unsigned int>(size),
				                                static_cast<unsigned int>(zeek::BifConst::AMQP::max_frame_size)));
		}

		return true;
		%}

	function validate_protocol_header(protocol_signature: uint16, version_prefix: uint32,
	                                  revision: uint8): bool
		%{
		if ( protocol_signature != 0x4d51 || version_prefix != 0x50000009 ||
		     revision != 1 )
			throw Exception("invalid AMQP protocol header");

		return true;
		%}
};
