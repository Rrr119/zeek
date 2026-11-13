// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/amqp/AMQP.h"

namespace zeek::plugin::detail::Zeek_AMQP {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("AMQP", zeek::analyzer::amqp::AMQP_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::AMQP";
        config.description = "Advanced Message Queuing Protocol 0-9-1 analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_AMQP
