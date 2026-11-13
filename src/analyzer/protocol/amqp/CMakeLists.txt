zeek_add_plugin(
    Zeek AMQP
    SOURCES AMQP.cc Plugin.cc
    BIFS consts.bif events.bif
    PAC amqp.pac amqp-protocol.pac amqp-analyzer.pac)
