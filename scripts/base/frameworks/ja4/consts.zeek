module JA4;

export {
	## Fingerprint kinds written to ``ja4.log``.
	const KIND_JA4 = "JA4";
	const KIND_JA4S = "JA4S";
	const KIND_JA4QUIC = "JA4QUIC";

	## GREASE values from :rfc:`8701`. These are ignored for all JA4 lists and
	## counts.
	const grease_values: set[count] = {
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	};

	## JA4's two-character TLS version components.
	const tls_version_codes: table[count] of string = {
		[0x0304] = "13",
		[0x0303] = "12",
		[0x0302] = "11",
		[0x0301] = "10",
		[0x0300] = "s3",
		[0x0200] = "s2",
		[0x0100] = "s1",
	} &default=function(v: count): string { return "00"; };
}

function is_grease(value: count): bool
	{
	return value in grease_values;
	}

function tls_version_code(value: count): string
	{
	# Map TLS 1.3 draft versions to 1.3 rather than losing them as unknown.
	if ( value / 0x100 == 0x7f )
		return "13";

	return tls_version_codes[value];
	}

function count_code(value: count): string
	{
	return value > 99 ? "99" : fmt("%02d", value);
	}

function hash12(value: string): string
	{
	return sub_bytes(sha256_hash(value), 0, 12);
	}

function alpn_code(protocol: string): string
	{
	if ( |protocol| == 0 )
		return "00";

	if ( ! is_ascii(protocol) )
		return "99";

	if ( |protocol| == 1 )
		return protocol + protocol;

	return protocol[0] + protocol[|protocol| - 1];
	}
