##! Group DHCP clients into clusters based on their option 55 parameter
##! request list fingerprint.  The base DHCP analyzer stores each client's
##! fingerprint in the ``dhcp_fingerprint`` field of :file:`dhcp.log`.
##! This policy script additionally maintains, for each distinct
##! fingerprint, the set of client hardware addresses (MACs) observed
##! with it in the :zeek:see:`DHCP::fingerprint_clusters` table and writes
##! the updated cluster to :file:`dhcp_fp_cluster.log` each time a new
##! client hardware address joins it.
##! Clients sharing a fingerprint request the same DHCP options in the
##! same order and typically belong to the same operating system or
##! device family, which makes the clusters useful for endpoint
##! fingerprinting.

@load base/protocols/dhcp

module DHCP;

export {
	## The log stream identifier for DHCP fingerprint clusters.
	redef enum Log::ID += { FINGERPRINT_CLUSTER_LOG };

	## A default logging policy hook for the fingerprint cluster stream.
	global log_policy_fingerprint_clusters: Log::PolicyHook;

	## The record type holding the fields of a fingerprint cluster.
	type FingerprintClusterInfo: record {
		## Time at which the cluster was first observed.
		ts:               time        &log;
		## The DHCP fingerprint shared by every client in the cluster.
		## It is the comma-separated option 55 parameter request list.
		dhcp_fingerprint: string      &log;
		## Number of distinct client hardware addresses observed with
		## this fingerprint.
		num_clients:      count       &log;
		## The hardware addresses (MACs) of the clients grouped into
		## this cluster.
		client_macs:      set[string] &log;
	};

	## The clusters keyed by DHCP fingerprint.  Each entry records when
	## the fingerprint was first seen and the client hardware addresses
	## observed with it.
	global fingerprint_clusters: table[string] of FingerprintClusterInfo &redef;

	## Generated when a client hardware address is added to a fingerprint
	## cluster, i.e. the first time that MAC is seen with a fingerprint.
	##
	## dhcp_fingerprint: the option 55 fingerprint of the client.
	##
	## mac: the client's hardware address.
	##
	## cluster: the updated cluster record.
	global new_fingerprint_cluster_member: event(dhcp_fingerprint: string,
	                                             mac: string,
	                                             cluster: FingerprintClusterInfo);

	## Event that can be handled to access a fingerprint cluster record
	## as it is sent on to the logging framework.
	global log_fingerprint_clusters: event(rec: FingerprintClusterInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(DHCP::FINGERPRINT_CLUSTER_LOG,
	                   Log::Stream($columns=FingerprintClusterInfo,
	                               $ev=log_fingerprint_clusters,
	                               $path="dhcp_fp_cluster",
	                               $policy=log_policy_fingerprint_clusters));
	}

event DHCP::log_dhcp(rec: Info)
	{
	if ( ! (rec?$dhcp_fingerprint && rec?$mac) )
		return;

	local fingerprint = rec$dhcp_fingerprint;
	local mac = rec$mac;

	if ( fingerprint !in fingerprint_clusters )
		fingerprint_clusters[fingerprint] = FingerprintClusterInfo(
			$ts=rec$ts,
			$dhcp_fingerprint=fingerprint,
			$num_clients=0,
			$client_macs=set());

	if ( mac !in fingerprint_clusters[fingerprint]$client_macs )
		{
		add fingerprint_clusters[fingerprint]$client_macs[mac];
		fingerprint_clusters[fingerprint]$num_clients =
			|fingerprint_clusters[fingerprint]$client_macs|;

		# Log the updated cluster whenever a new client joins it.
		# Runtime state stays available in fingerprint_clusters.
		Log::write(DHCP::FINGERPRINT_CLUSTER_LOG,
		           fingerprint_clusters[fingerprint]);
		event new_fingerprint_cluster_member(fingerprint, mac,
		                                     fingerprint_clusters[fingerprint]);
		}
	}
