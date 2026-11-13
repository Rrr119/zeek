# @TEST-DOC: Baseline JA4/JA4S output for existing TLS 1.2 and TLS 1.3 pcaps.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/tls/tls1.2.pcap %INPUT
# @TEST-EXEC: zeek-cut uid kind fingerprint prefix raw label < ja4.log >ja4-tls12.log
# @TEST-EXEC: rm ja4.log
# @TEST-EXEC: zeek -b -C -r $TRACES/tls/tls13_wolfssl.pcap %INPUT
# @TEST-EXEC: zeek-cut uid kind fingerprint prefix raw label < ja4.log >ja4-tls13.log
# @TEST-EXEC: btest-diff ja4-tls12.log
# @TEST-EXEC: btest-diff ja4-tls13.log

@load base/frameworks/ja4

event zeek_init()
	{
	JA4::add_prefix_label("t12", "tls12");
	JA4::add_prefix_label("t13", "tls13");
	}
