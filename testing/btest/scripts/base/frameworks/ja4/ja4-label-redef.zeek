# @TEST-DOC: JA4 fingerprints can be labeled by redefining the label function.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/ja4-alpn-order.pcap %INPUT
# @TEST-EXEC: test "$(zeek-cut label < ja4.log | sort -u | wc -l)" -eq 1
# @TEST-EXEC: test "$(zeek-cut label < ja4.log | head -1)" = "custom-tls13"
# @TEST-EXEC: btest-diff-cut -m uid kind fingerprint label ja4.log

@load base/frameworks/ja4

redef JA4::fingerprint_label = function(fingerprint: string): string {
	return starts_with(fingerprint, "t13") ? "custom-tls13" : "other";
};
