##! JA4, JA4S, and JA4QUIC fingerprints for TLS and QUIC handshakes.
##!
##! JA4 fingerprints are emitted to ``ja4.log`` with one record per fingerprint
##! kind. The log's ``uid`` field joins the records to ``conn.log``.
##!
##! The published JA4 specification sorts cipher suites and extension types
##! before hashing to make fingerprints robust against per-connection list
##! randomization. This script follows that behavior by default. It also records
##! an order-sensitive ``ordered_fingerprint`` variant that preserves the wire
##! order of extension types. Set :zeek:see:`JA4::use_wire_extension_order` to
##! use that variant as the primary ``fingerprint`` value.
##!
##! Repeated ClientHello/ServerHello shapes are served from a bounded cache so
##! the common case avoids sorting and hashing lists for every handshake.

module JA4;

export {
	redef enum Log::ID += { LOG };

	## One fingerprint result. A TLS connection may produce separate JA4 and
	## JA4S records, correlated through ``uid``.
	type Info: record {
		## Timestamp when the fingerprint was completed.
		ts: time &log;
		## Unique connection ID, matching ``conn.log``.
		uid: string &log;
		## Connection endpoints.
		id: conn_id &log;
		## One of ``JA4``, ``JA4S``, or ``JA4QUIC``.
		kind: string &log;
		## The complete JA4-family fingerprint.
		fingerprint: string &log;
		## The fingerprint's human-readable protocol/version/SNI/ALPN/count
		## prefix, for example ``t13d1516h2``.
		prefix: string &log;
		## Unhashed wire-order data used to build the fingerprint.
		raw: string &log;
		## Extension-order-sensitive variant using the same prefix and cipher
		## hash. This differs from ``fingerprint`` only when extension types are
		## reordered (and the option below is left at its default).
		ordered_fingerprint: string &log;
		## Label assigned by :zeek:see:`JA4::fingerprint_label`.
		label: string &log &default="";
	};

	## Event raised for each written JA4 log record.
	global log_ja4: event(rec: Info);

	## Logging policy hook.
	global log_policy: Log::PolicyHook;

	## Use wire order rather than sorted order for extension types in the
	## primary ``fingerprint`` hash.
	##
	## The default is *F* to match published JA4. The order-sensitive variant is
	## always available in ``ordered_fingerprint``.
	option use_wire_extension_order = F;

	## Maximum number of distinct handshake shapes retained by the fingerprint
	## cache. Once full, new shapes are still fingerprinted but not cached.
	option max_cache_entries = 4096;

	## Maximum cache-key length in bytes. Larger handshakes are fingerprinted
	## but not cached, bounding retained state for unusual ClientHellos.
	option max_cache_key_length = 2048;

	## Prefix labels consulted by the default :zeek:see:`fingerprint_label`
	## implementation. The longest matching non-empty prefix wins.
	global prefix_labels: table[string] of string &redef;

	## Override point for assigning labels to fingerprints. Scripts may redefine
	## this function, or populate :zeek:see:`prefix_labels` via
	## :zeek:see:`add_prefix_label`.
	global fingerprint_label: function(fingerprint: string): string = function(fingerprint: string): string {
		local best_label = "";
		local best_length = 0;

		for ( prefix in prefix_labels )
			{
			if ( |prefix| == 0 || |prefix| <= best_length )
				next;

			if ( starts_with(fingerprint, prefix) )
				{
				best_label = prefix_labels[prefix];
				best_length = |prefix|;
				}
			}

		return best_label;
	} &redef;

	## Add or replace a prefix label.
	global add_prefix_label: function(prefix: string, label: string): bool;

	## Remove a prefix label.
	global remove_prefix_label: function(prefix: string): bool;

	## Number of fingerprint computations served by the cache.
	global cache_hit_count: count = 0;

	## Number of fingerprint computations not served by the cache.
	global cache_miss_count: count = 0;

	## Drop all cached fingerprints.
	global clear_cache: function();
}

type ClientHello: record {
	version: count &default=0;
	ciphers: vector of string &default=vector();
	extensions: vector of string &default=vector();
	supported_versions: vector of count &default=vector();
	signature_algorithms: vector of string &default=vector();
	has_sni: bool &default=F;
	alpn: string &default="";
	done: bool &default=F;
};

type ServerHello: record {
	version: count &default=0;
	cipher: count &default=0;
	extensions: vector of string &default=vector();
	supported_versions: vector of count &default=vector();
	alpn: string &default="";
	done: bool &default=F;
};

type ConnectionState: record {
	client: ClientHello &default=ClientHello();
	server: ServerHello &default=ServerHello();
};

type CachedFingerprint: record {
	fingerprint: string;
	ordered_fingerprint: string;
	prefix: string;
	raw: string;
};

redef record connection += {
	ja4: ConnectionState &optional;
};

global fingerprint_cache: table[string] of CachedFingerprint;

function add_prefix_label(prefix: string, label: string): bool
	{
	if ( |prefix| == 0 )
		return F;

	prefix_labels[prefix] = label;
	return T;
	}

function remove_prefix_label(prefix: string): bool
	{
	if ( prefix !in prefix_labels )
		return F;

	delete prefix_labels[prefix];
	return T;
	}

function clear_cache()
	{
	clear_table(fingerprint_cache);
	}

function get_state(c: connection): ConnectionState
	{
	if ( ! c?$ja4 )
		c$ja4 = ConnectionState();

	return c$ja4;
	}

function is_quic(c: connection): bool
	{
@ifdef ( Analyzer::ANALYZER_QUIC )
	if ( c?$quic )
		return T;
@endif

	return "QUIC" in c$service;
	}

function transport_code(c: connection): string
	{
	return is_quic(c) ? "q" : "t";
	}

function effective_client_version(state: ClientHello): count
	{
	local version = state$version;

	for ( i in state$supported_versions )
		{
		local candidate = state$supported_versions[i];
		if ( ! is_grease(candidate) && candidate > version )
			version = candidate;
		}

	return version;
	}

function effective_server_version(state: ServerHello): count
	{
	local version = state$version;

	for ( i in state$supported_versions )
		{
		local candidate = state$supported_versions[i];
		if ( ! is_grease(candidate) && candidate > version )
			version = candidate;
		}

	return version;
	}

function signature_part(signature_algorithms: vector of string): string
	{
	if ( |signature_algorithms| == 0 )
		return "";

	return "_" + join_string_vec(signature_algorithms, ",");
	}

function sorted_copy(values: vector of string): vector of string
	{
	local result: vector of string = vector();
	for ( i in values )
		result += values[i];

	sort(result, strcmp);
	return result;
	}

function client_cache_key(proto: string, state: ClientHello): string
	{
	local sni = state$has_sni ? "1" : "0";

	return fmt("c|%s|%d|%s|%d:%s|%s|%s|%s",
	           proto, effective_client_version(state), sni,
	           |state$alpn|, state$alpn,
	           join_string_vec(state$ciphers, ","),
	           join_string_vec(state$extensions, ","),
	           join_string_vec(state$signature_algorithms, ","));
	}

function server_cache_key(proto: string, state: ServerHello): string
	{
	return fmt("s|%s|%d|%d:%s|%s|%d",
	           proto, effective_server_version(state),
	           |state$alpn|, state$alpn,
	           join_string_vec(state$extensions, ","), state$cipher);
	}

function compute_client_fingerprint(proto: string, state: ClientHello): CachedFingerprint
	{
	local prefix = proto;
	prefix += tls_version_code(effective_client_version(state));
	prefix += state$has_sni ? "d" : "i";
	prefix += count_code(|state$ciphers|);
	prefix += count_code(|state$extensions|);
	prefix += alpn_code(state$alpn);

	local sorted_ciphers = sorted_copy(state$ciphers);
	local cipher_hash = hash12(join_string_vec(sorted_ciphers, ","));

	local wire_extensions: vector of string = vector();
	local sorted_extensions: vector of string = vector();

	for ( i in state$extensions )
		{
		local code = state$extensions[i];
		if ( code == "0000" || code == "0010" )
			next;

		wire_extensions += code;
		sorted_extensions += code;
		}

	sort(sorted_extensions, strcmp);

	local sig_part = signature_part(state$signature_algorithms);
	local wire_hash = hash12(join_string_vec(wire_extensions, ",") + sig_part);
	local sorted_hash = hash12(join_string_vec(sorted_extensions, ",") + sig_part);

	local fingerprint_extension_hash = use_wire_extension_order ? wire_hash : sorted_hash;
	local raw = fmt("%s_%s_%s%s",
	                prefix,
	                join_string_vec(state$ciphers, ","),
	                join_string_vec(state$extensions, ","),
	                sig_part);

	return CachedFingerprint(
		$fingerprint=prefix + "_" + cipher_hash + "_" + fingerprint_extension_hash,
		$ordered_fingerprint=prefix + "_" + cipher_hash + "_" + wire_hash,
		$prefix=prefix,
		$raw=raw);
	}

function compute_server_fingerprint(proto: string, state: ServerHello): CachedFingerprint
	{
	local prefix = proto;
	prefix += tls_version_code(effective_server_version(state));
	prefix += count_code(|state$extensions|);
	prefix += alpn_code(state$alpn);

	local cipher = fmt("%04x", state$cipher);
	local extensions = join_string_vec(state$extensions, ",");
	local fingerprint = prefix + "_" + cipher + "_" + hash12(extensions);
	local raw = prefix + "_" + cipher + "_" + extensions;

	return CachedFingerprint(
		$fingerprint=fingerprint,
		$ordered_fingerprint=fingerprint,
		$prefix=prefix,
		$raw=raw);
	}

function write_fingerprint(c: connection, kind: string, value: CachedFingerprint)
	{
	local info = Info(
		$ts=network_time(),
		$uid=c$uid,
		$id=c$id,
		$kind=kind,
		$fingerprint=value$fingerprint,
		$prefix=value$prefix,
		$raw=value$raw,
		$ordered_fingerprint=value$ordered_fingerprint,
		$label=fingerprint_label(value$fingerprint));

	Log::write(LOG, info);
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string) &priority=5
	{
	if ( is_grease(code) )
		return;

	local state = get_state(c);

	if ( is_client )
		{
		if ( state$client$done )
			return;

		state$client$extensions += fmt("%04x", code);
		if ( code == SSL::SSL_EXTENSION_SERVER_NAME )
			state$client$has_sni = T;
		}
	else
		{
		if ( state$server$done )
			return;

		state$server$extensions += fmt("%04x", code);
		}
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	local state = get_state(c);

	if ( is_client )
		{
		if ( ! state$client$done && |protocols| > 0 )
			state$client$alpn = protocols[0];
		}
	else if ( ! state$server$done && |protocols| > 0 )
		state$server$alpn = protocols[0];
	}

event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_algorithms: signature_and_hashalgorithm_vec)
	{
	if ( ! is_client )
		return;

	local state = get_state(c);
	if ( state$client$done )
		return;

	for ( i in signature_algorithms )
		{
		local algorithm = signature_algorithms[i];
		local value = (algorithm$HashAlgorithm << 8) | algorithm$SignatureAlgorithm;

		if ( ! is_grease(value) )
			state$client$signature_algorithms += fmt("%04x", value);
		}
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	local state = get_state(c);

	if ( is_client )
		{
		if ( state$client$done )
			return;

		for ( i in versions )
			if ( ! is_grease(versions[i]) )
				state$client$supported_versions += versions[i];
		}
	else
		{
		if ( state$server$done )
			return;

		for ( i in versions )
			if ( ! is_grease(versions[i]) )
				state$server$supported_versions += versions[i];
		}
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
                       client_random: string, session_id: string, ciphers: index_vec,
                       comp_methods: index_vec)
	{
	local state = get_state(c);
	if ( state$client$done )
		return;

	state$client$version = version;
	for ( i in ciphers )
		if ( ! is_grease(ciphers[i]) )
			state$client$ciphers += fmt("%04x", ciphers[i]);

	state$client$done = T;

	local proto = transport_code(c);
	local key = client_cache_key(proto, state$client);
	local value: CachedFingerprint;

	if ( key in fingerprint_cache )
		{
		++cache_hit_count;
		value = fingerprint_cache[key];
		}
	else
		{
		++cache_miss_count;
		value = compute_client_fingerprint(proto, state$client);
		if ( |fingerprint_cache| < max_cache_entries &&
		     |key| <= max_cache_key_length )
			fingerprint_cache[key] = value;
		}

	write_fingerprint(c, is_quic(c) ? KIND_JA4QUIC : KIND_JA4, value);
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time,
                       server_random: string, session_id: string, cipher: count,
                       comp_method: count)
	{
	local state = get_state(c);
	if ( state$server$done )
		return;

	state$server$version = version;
	state$server$cipher = cipher;
	state$server$done = T;

	local proto = transport_code(c);
	local key = server_cache_key(proto, state$server);
	local value: CachedFingerprint;

	if ( key in fingerprint_cache )
		{
		++cache_hit_count;
		value = fingerprint_cache[key];
		}
	else
		{
		++cache_miss_count;
		value = compute_server_fingerprint(proto, state$server);
		if ( |fingerprint_cache| < max_cache_entries &&
		     |key| <= max_cache_key_length )
			fingerprint_cache[key] = value;
		}

	write_fingerprint(c, KIND_JA4S, value);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_ja4, $path="ja4",
	                                  $policy=log_policy));
	}
