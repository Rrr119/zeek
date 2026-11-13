# Analyzer for AMQP 0-9-1.

%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/amqp/AMQP.h"
	#include "zeek/analyzer/protocol/amqp/consts.bif.h"
	#include "zeek/analyzer/protocol/amqp/events.bif.h"
%}

analyzer AMQP withcontext {
	connection: AMQP_Conn;
	flow:       AMQP_Flow;
};

connection AMQP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = AMQP_Flow(true);
	downflow = AMQP_Flow(false);
};

%include amqp-protocol.pac

flow AMQP_Flow(is_orig: bool) {
	flowunit = AMQP_PDU(is_orig) withcontext(connection, this);
};

%include amqp-analyzer.pac
