.. _opcua-log:

OPC UA
======

Zeek's OPC UA analyzer decodes the binary protocol used by OPC UA TCP
endpoints, typically on port 4840. It emits one :file:`opcua.log` record for
each transport message or reassembled service message.

Supported messages
------------------

The analyzer parses:

* Hello and Acknowledge transport messages, including the endpoint URL
* OpenSecureChannel request and response
* GetEndpoints request and response
* CreateSession request and response
* Read and Write request and response
* CreateSubscription request and response
* Publish request and response
* ServiceFault and CloseSecureChannel messages

TCP reassembly and OPC UA chunk handling are supported. A service message
split across multiple ``C`` (continuation) chunks and a final ``F`` chunk is
concatenated before the service body is decoded. The analyzer also extracts
NodeIds, ExtensionObject type NodeIds, StatusCodes, endpoint URLs, security
policy URIs, message security modes, session NodeIds, request identifiers,
and subscription identifiers.

The log contains the following key fields:

* ``service``: decoded service name, such as ``ReadRequest`` or
  ``PublishResponse``
* ``message_type``: transport message type (``HEL``, ``ACK``, ``OPN``,
  ``MSG``, ``CLO``, or ``ABO``)
* ``endpoint``: most recently observed endpoint URL
* ``security_policy``: most recently observed OPC UA security policy URI
* ``security_mode``: ``None``, ``Sign``, or ``SignAndEncrypt``
* ``status`` and ``status_code``: StatusCode value and symbolic name
* ``session_id`` and ``subscription_id``: observed session and subscription
  identifiers
* ``chunk_type`` and ``chunk_count``: chunk reassembly details
* ``node_ids`` and ``extension_objects``: NodeIds and ExtensionObject type
  NodeIds extracted from the message

For service responses with per-operation results, such as Read and Write,
``status`` reflects the first non-Good operation status. If all operation
statuses are Good, it reflects the response service result.

Limitations
-----------

The analyzer only decodes clear-text service bodies. Messages negotiated with
``SignAndEncrypt`` are logged as ``Encrypted`` after their transport,
secure-channel, security-policy, request, and sequence headers have been
parsed. It does not decrypt traffic, validate certificates, reconstruct the
OPC UA information model, or decode browse paths, method arguments,
monitored-item filters, and event-filter contents.

GetEndpoints and CreateSession responses can carry multiple endpoint
descriptions. The first description supplies the endpoint URL and security
policy used for the current log record; the remaining descriptions are
validated but not emitted as separate records. Abort and CloseSecureChannel
support is limited to transport headers and basic StatusCodes.

Malformed chunk lengths, messages larger than
:zeek:id:`OPCUA::max_message_size`, and TCP gaps raise an analyzer violation
and stop further OPC UA decoding for the connection.

Configuration
-------------

The analyzer registers TCP port 4840 and uses a DPD signature that recognizes
Hello messages on other ports. Additional ports can be configured with
:zeek:id:`OPCUA::ports`. Resource limits are configurable through
:zeek:id:`OPCUA::max_message_size`, :zeek:id:`OPCUA::max_node_ids`, and
:zeek:id:`OPCUA::max_extension_objects`.
