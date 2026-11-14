signature dpd_opcua_hello {
	ip-proto == tcp
	payload /^HELF/
	enable "opcua"
}
