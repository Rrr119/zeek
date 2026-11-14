zeek_add_plugin(
    Zeek OPCUA
    SOURCES OPCUA.cc Plugin.cc
    BIFS events.bif consts.bif)
