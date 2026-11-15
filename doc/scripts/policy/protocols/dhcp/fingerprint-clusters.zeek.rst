:tocdepth: 3

policy/protocols/dhcp/fingerprint-clusters.zeek
===============================================
.. zeek:namespace:: DHCP

Group DHCP clients into clusters based on their option 55 parameter
request list fingerprint.  The base DHCP analyzer stores each client's
fingerprint in the ``dhcp_fingerprint`` field of :file:`dhcp.log`.
This policy script additionally maintains, for each distinct
fingerprint, the set of client hardware addresses (MACs) observed
with it in the :zeek:see:`DHCP::fingerprint_clusters` table and writes
the updated cluster to :file:`dhcp_fp_cluster.log` each time a new
client hardware address joins it.
Clients sharing a fingerprint request the same DHCP options in the
same order and typically belong to the same operating system or
device family, which makes the clusters useful for endpoint
fingerprinting.

:Namespace: DHCP
:Imports: :doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

Summary
~~~~~~~
State Variables
###############
============================================================================= =======================================
:zeek:id:`DHCP::fingerprint_clusters`: :zeek:type:`table` :zeek:attr:`&redef` The clusters keyed by DHCP fingerprint.
============================================================================= =======================================

Types
#####
============================================================== ============================================================
:zeek:type:`DHCP::FingerprintClusterInfo`: :zeek:type:`record` The record type holding the fields of a fingerprint cluster.
============================================================== ============================================================

Redefinitions
#############
======================================= ========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The log stream identifier for DHCP fingerprint clusters.

                                        * :zeek:enum:`DHCP::FINGERPRINT_CLUSTER_LOG`
======================================= ========================================================

Events
######
=================================================================== ==================================================================
:zeek:id:`DHCP::log_fingerprint_clusters`: :zeek:type:`event`       Event that can be handled to access a fingerprint cluster record
                                                                    as it is sent on to the logging framework.
:zeek:id:`DHCP::new_fingerprint_cluster_member`: :zeek:type:`event` Generated when a client hardware address is added to a fingerprint
                                                                    cluster, i.e.
=================================================================== ==================================================================

Hooks
#####
============================================================================== =================================================================
:zeek:id:`DHCP::log_policy_fingerprint_clusters`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the fingerprint cluster stream.
============================================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: DHCP::fingerprint_clusters
   :source-code: policy/protocols/dhcp/fingerprint-clusters.zeek 43 43

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`DHCP::FingerprintClusterInfo`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   The clusters keyed by DHCP fingerprint.  Each entry records when
   the fingerprint was first seen and the client hardware addresses
   observed with it.

Types
#####
.. zeek:type:: DHCP::FingerprintClusterInfo
   :source-code: policy/protocols/dhcp/fingerprint-clusters.zeek 26 38

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Time at which the cluster was first observed.


   .. zeek:field:: dhcp_fingerprint :zeek:type:`string` :zeek:attr:`&log`

      The DHCP fingerprint shared by every client in the cluster.
      It is the comma-separated option 55 parameter request list.


   .. zeek:field:: num_clients :zeek:type:`count` :zeek:attr:`&log`

      Number of distinct client hardware addresses observed with
      this fingerprint.


   .. zeek:field:: client_macs :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log`

      The hardware addresses (MACs) of the clients grouped into
      this cluster.


   The record type holding the fields of a fingerprint cluster.

Events
######
.. zeek:id:: DHCP::log_fingerprint_clusters
   :source-code: policy/protocols/dhcp/fingerprint-clusters.zeek 59 59

   :Type: :zeek:type:`event` (rec: :zeek:type:`DHCP::FingerprintClusterInfo`)

   Event that can be handled to access a fingerprint cluster record
   as it is sent on to the logging framework.

.. zeek:id:: DHCP::new_fingerprint_cluster_member
   :source-code: policy/protocols/dhcp/fingerprint-clusters.zeek 53 53

   :Type: :zeek:type:`event` (dhcp_fingerprint: :zeek:type:`string`, mac: :zeek:type:`string`, cluster: :zeek:type:`DHCP::FingerprintClusterInfo`)

   Generated when a client hardware address is added to a fingerprint
   cluster, i.e. the first time that MAC is seen with a fingerprint.


   :param dhcp_fingerprint: the option 55 fingerprint of the client.


   :param mac: the client's hardware address.


   :param cluster: the updated cluster record.

Hooks
#####
.. zeek:id:: DHCP::log_policy_fingerprint_clusters
   :source-code: policy/protocols/dhcp/fingerprint-clusters.zeek 23 23

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the fingerprint cluster stream.


