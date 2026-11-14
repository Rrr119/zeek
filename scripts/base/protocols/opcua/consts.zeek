##! Constants for the OPC UA binary protocol analyzer.

module OPCUA;

export {
	## Well-known TCP port for OPC UA binary transport.
	const ports = { 4840/tcp } &redef;
}
