// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::opcua {

class OPCUA_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit OPCUA_Analyzer(Connection* conn);

    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new OPCUA_Analyzer(conn); }

private:
    struct Reader {
        Reader(const uint8_t* data, size_t len);

        size_t Remaining() const { return length - position; }
        const uint8_t* Current() const { return data + position; }

        bool Skip(size_t count);
        bool U8(uint8_t& value);
        bool U16(uint16_t& value);
        bool U32(uint32_t& value);
        bool I32(int32_t& value);
        bool U64(uint64_t& value);
        bool F64(double& value);
        bool Boolean(bool& value);
        bool String(std::string& value, bool allow_null = true);
        bool ByteString(std::string* value = nullptr);
        bool NodeId(std::string& value);
        bool ExpandedNodeId(std::string& value);
        bool QualifiedName();
        bool LocalizedText();
        bool DiagnosticInfo(unsigned depth = 0);
        bool ExtensionObject(std::string* type_id, unsigned depth = 0);
        bool Variant(unsigned depth = 0);
        bool DataValue(uint32_t* status, bool* has_status, unsigned depth = 0);
        bool ArrayLength(uint32_t& count, bool allow_null = true);

    private:
        const uint8_t* data;
        size_t length;
        size_t position = 0;
        bool good = true;
    };

    struct MessageInfo {
        std::string message_type;
        std::string service;
        std::string endpoint;
        std::string security_policy;
        std::string security_mode;
        std::string session_id;
        std::string chunk_type;
        std::vector<std::string> node_ids;
        std::vector<std::string> extension_objects;
        uint32_t status = 0;
        uint32_t subscription_id = 0;
        uint32_t request_id = 0;
        uint32_t chunk_count = 1;
        uint32_t message_size = 0;
        bool has_status = false;
        bool has_subscription = false;
    };

    struct PendingRequest {
        std::vector<std::string> node_ids;
    };

    struct DirectionState {
        std::vector<uint8_t> input;
        size_t input_offset = 0;
        std::vector<uint8_t> chunk_data;
        std::string chunk_message_type;
        std::string chunk_type;
        std::string security_policy;
        uint32_t chunk_request_id = 0;
        uint32_t chunk_count = 0;
        uint32_t last_message_size = 0;
        bool assembling = false;
        bool disabled = false;
    };

    void ProcessInput(bool orig);
    bool ProcessChunk(DirectionState& state, const uint8_t* data, size_t len, bool orig);
    bool ProcessHello(DirectionState& state, const uint8_t* type, size_t len, bool orig);
    bool ProcessSecureChunk(DirectionState& state, const uint8_t* type, const uint8_t* data, size_t len, bool orig);
    bool FinishMessage(DirectionState& state, bool orig);
    bool ParseServicePayload(MessageInfo& info, Reader& reader, bool orig, bool& response);
    bool ParseOpenSecureChannel(MessageInfo& info, Reader& reader, bool response);
    bool ParseGetEndpoints(MessageInfo& info, Reader& reader, bool response);
    bool ParseCreateSession(MessageInfo& info, Reader& reader, bool response);
    bool ParseRead(MessageInfo& info, Reader& reader, bool response);
    bool ParseWrite(MessageInfo& info, Reader& reader, bool response);
    bool ParseCreateSubscription(MessageInfo& info, Reader& reader, bool response);
    bool ParsePublish(MessageInfo& info, Reader& reader, bool response);

    bool ParseRequestHeader(Reader& reader, std::string* auth_token = nullptr);
    bool ParseResponseHeader(Reader& reader, MessageInfo& info);
    bool ParseApplicationDescription(Reader& reader);
    bool ParseEndpointDescription(Reader& reader, std::string& endpoint, std::string& policy,
                                  std::string& security_mode);
    bool ParseEndpointDescriptions(Reader& reader, uint32_t count, std::string& endpoint, std::string& policy,
                                   std::string& security_mode);
    void AddNodeId(MessageInfo& info, const std::string& node_id);
    void AddExtensionObject(MessageInfo& info, const std::string& type_id);
    void Emit(MessageInfo& info, bool orig);
    void UpdateContext(const MessageInfo& info);
    void SetFailure(const char* reason);
    void Compact(DirectionState& state);

    DirectionState orig_state;
    DirectionState resp_state;

    std::map<uint32_t, PendingRequest> pending_requests;
    std::string endpoint;
    std::string security_policy;
    std::string security_mode;
    std::string session_id;
    uint32_t max_message_size = 0;
    uint32_t max_node_ids = 0;
    uint32_t max_extension_objects = 0;
    bool saw_protocol = false;
    bool disabled = false;
};

} // namespace zeek::analyzer::opcua
