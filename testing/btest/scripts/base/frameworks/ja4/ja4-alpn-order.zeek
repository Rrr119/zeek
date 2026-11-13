# @TEST-DOC: JA4 changes when only ALPN list order changes, while JA3 stays equal.
#
# Both handshakes carry the same cipher suites, extension types, groups, point
# formats, SNI, and signature algorithms. The only difference is the order of
# the ALPN protocol values. JA3 does not hash ALPN values, but JA4 includes the
# first ALPN value's first/last characters in its readable prefix.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/ja4-alpn-order.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test "$(sort -u out | wc -l)" -eq 1
# @TEST-EXEC: test "$(zeek-cut kind fingerprint < ja4.log | awk '$1 == "JA4" { print $2 }' | sort -u | wc -l)" -eq 2
# @TEST-EXEC: test "$(zeek-cut kind ordered_fingerprint < ja4.log | awk '$1 == "JA4" { print $2 }' | sort -u | wc -l)" -eq 2
# @TEST-EXEC: btest-diff-cut -m uid kind fingerprint prefix ordered_fingerprint raw label ja4.log

@load base/frameworks/ja4

type JA3State: record {
	extensions: vector of string &default=vector();
	curves: vector of string &default=vector();
	point_formats: vector of string &default=vector();
	done: bool &default=F;
};

global ja3_states: table[string] of JA3State;

function ja3_state(c: connection): JA3State
	{
	if ( c$uid !in ja3_states )
		ja3_states[c$uid] = JA3State();

	return ja3_states[c$uid];
	}

event zeek_init()
	{
	JA4::add_prefix_label("t13", "tls13");
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	if ( ! is_client )
		return;

	local state = ja3_state(c);
	if ( ! state$done )
		state$extensions += fmt("%d", code);
	}

event ssl_extension_elliptic_curves(c: connection, is_client: bool, curves: index_vec)
	{
	if ( ! is_client )
		return;

	local state = ja3_state(c);
	if ( state$done )
		return;

	for ( i in curves )
		state$curves += fmt("%d", curves[i]);
	}

event ssl_extension_ec_point_formats(c: connection, is_client: bool, point_formats: index_vec)
	{
	if ( ! is_client )
		return;

	local state = ja3_state(c);
	if ( state$done )
		return;

	for ( i in point_formats )
		state$point_formats += fmt("%d", point_formats[i]);
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
                       client_random: string, session_id: string, ciphers: index_vec,
                       comp_methods: index_vec)
	{
	local state = ja3_state(c);
	if ( state$done )
		return;

	local cipher_list: vector of string = vector();
	for ( i in ciphers )
		cipher_list += fmt("%d", ciphers[i]);

	local ja3_input = fmt("%d,%s,%s,%s,%s",
	                      version,
	                      join_string_vec(cipher_list, "-"),
	                      join_string_vec(state$extensions, "-"),
	                      join_string_vec(state$curves, "-"),
	                      join_string_vec(state$point_formats, "-"));

	print md5_hash(ja3_input);
	state$done = T;
	}
