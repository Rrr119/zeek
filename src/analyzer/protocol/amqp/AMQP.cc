// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/amqp/AMQP.h"

#include "zeek/Reporter.h"

#include "analyzer/protocol/amqp/amqp_pac.h"

namespace zeek::analyzer::amqp {

AMQP_Analyzer::AMQP_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("AMQP", c) {
    interp = new binpac::AMQP::AMQP_Conn(this);
}

AMQP_Analyzer::~AMQP_Analyzer() { delete interp; }

void AMQP_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    interp->FlowEOF(true);
    interp->FlowEOF(false);
}

void AMQP_Analyzer::EndpointEOF(bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

void AMQP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.what()));
    }
}

void AMQP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    interp->NewGap(orig, len);
}

} // namespace zeek::analyzer::amqp
