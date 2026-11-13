// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace binpac {
namespace AMQP {
class AMQP_Conn;
}
} // namespace binpac

namespace zeek::analyzer::amqp {

class AMQP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit AMQP_Analyzer(Connection* conn);
    ~AMQP_Analyzer() override;

    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new AMQP_Analyzer(conn); }

protected:
    binpac::AMQP::AMQP_Conn* interp;
};

} // namespace zeek::analyzer::amqp
