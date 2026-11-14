// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/opcua/OPCUA.h"

namespace zeek::plugin::detail::Zeek_OPCUA {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("OPCUA", zeek::analyzer::opcua::OPCUA_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::OPCUA";
        config.description = "OPC UA binary protocol analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_OPCUA
