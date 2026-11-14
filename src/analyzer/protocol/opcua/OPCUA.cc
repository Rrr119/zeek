// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/opcua/OPCUA.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/analyzer/protocol/opcua/consts.bif.h"
#include "zeek/analyzer/protocol/opcua/events.bif.h"
#include "zeek/util.h"

namespace zeek::analyzer::opcua {
namespace {

constexpr size_t MAX_CAPTURED_STRING = 2048;
constexpr uint32_t MAX_ARRAY_ITEMS = 65536;
constexpr uint32_t MAX_CHUNKS = 65535;
constexpr unsigned MAX_RECURSION = 16;
constexpr size_t MAX_PENDING_REQUESTS = 256;

std::string ShortString(const std::string& value) {
    if ( value.size() <= MAX_CAPTURED_STRING )
        return value;

    return value.substr(0, MAX_CAPTURED_STRING) + "...";
}

std::string FormatNodeId(uint16_t ns, std::string_view kind, const std::string& value) {
    if ( ns == 0 )
        return std::string(kind) + "=" + value;

    return "ns=" + std::to_string(ns) + ";" + std::string(kind) + "=" + value;
}

std::string StatusCodeName(uint32_t code) {
    switch ( code ) {
        case 0x00000000: return "Good";
        case 0x40000000: return "Uncertain";
        case 0x80000000: return "Bad";
        case 0x80010000: return "BadUnexpectedError";
        case 0x80020000: return "BadInternalError";
        case 0x80030000: return "BadOutOfMemory";
        case 0x80040000: return "BadResourceUnavailable";
        case 0x80050000: return "BadCommunicationError";
        case 0x80060000: return "BadEncodingError";
        case 0x80070000: return "BadDecodingError";
        case 0x80080000: return "BadEncodingLimitsExceeded";
        case 0x80090000: return "BadUnknownResponse";
        case 0x800A0000: return "BadTimeout";
        case 0x800B0000: return "BadServiceUnsupported";
        case 0x800C0000: return "BadShutdown";
        case 0x800D0000: return "BadServerNotConnected";
        case 0x800E0000: return "BadServerHalted";
        case 0x800F0000: return "BadNothingToDo";
        case 0x80100000: return "BadTooManyOperations";
        case 0x80110000: return "BadDataTypeIdUnknown";
        case 0x80120000: return "BadCertificateInvalid";
        case 0x80130000: return "BadSecurityChecksFailed";
        case 0x80190000: return "BadIdentityTokenInvalid";
        case 0x801A0000: return "BadIdentityTokenRejected";
        case 0x801B0000: return "BadSecureChannelIdInvalid";
        case 0x801C0000: return "BadInvalidTimestamp";
        case 0x801D0000: return "BadNonceInvalid";
        case 0x801E0000: return "BadSessionIdInvalid";
        case 0x801F0000: return "BadSessionClosed";
        case 0x80200000: return "BadSessionNotActivated";
        case 0x80210000: return "BadSubscriptionIdInvalid";
        case 0x80220000: return "BadRequestHeaderInvalid";
        case 0x80230000: return "BadTimestampsToReturnInvalid";
        case 0x80240000: return "BadRequestCancelledByClient";
        case 0x80250000: return "BadTooManyArguments";
        case 0x80290000: return "BadNoSubscription";
        case 0x802A0000: return "BadMonitoredItemIdInvalid";
        case 0x80300000: return "BadContinuationPointInvalid";
        case 0x80310000: return "BadNoContinuationPoints";
        case 0x80320000: return "BadReferenceTypeIdInvalid";
        case 0x80330000: return "BadBrowseDirectionInvalid";
        case 0x80340000: return "BadNodeIdInvalid";
        case 0x80350000: return "BadNodeIdUnknown";
        case 0x80360000: return "BadAttributeIdInvalid";
        case 0x80370000: return "BadIndexRangeInvalid";
        case 0x80380000: return "BadIndexRangeNoData";
        case 0x803B0000: return "BadNotReadable";
        case 0x803C0000: return "BadNotWritable";
        case 0x803D0000: return "BadOutOfRange";
        case 0x803E0000: return "BadNotSupported";
        case 0x803F0000: return "BadNotFound";
        case 0x80400000: return "BadObjectDeleted";
        case 0x80410000: return "BadNotImplemented";
        default:
            if ( (code & 0xC0000000u) == 0x80000000u )
                return util::fmt("Bad-0x%08X", code);
            if ( (code & 0xC0000000u) == 0x40000000u )
                return util::fmt("Uncertain-0x%08X", code);
            return util::fmt("0x%08X", code);
    }
}

std::string SecurityModeName(uint32_t mode) {
    switch ( mode ) {
        case 0: return "Invalid";
        case 1: return "None";
        case 2: return "Sign";
        case 3: return "SignAndEncrypt";
        default: return "Unknown-" + std::to_string(mode);
    }
}

const char* ServiceName(uint32_t id, bool& response) {
    response = false;
    switch ( id ) {
        case 397: response = true; return "ServiceFault";
        case 422: return "FindServersRequest";
        case 425: response = true; return "FindServersResponse";
        case 428: return "GetEndpointsRequest";
        case 431: response = true; return "GetEndpointsResponse";
        case 446: return "OpenSecureChannelRequest";
        case 449: response = true; return "OpenSecureChannelResponse";
        case 452: return "CloseSecureChannelRequest";
        case 455: response = true; return "CloseSecureChannelResponse";
        case 461: return "CreateSessionRequest";
        case 464: response = true; return "CreateSessionResponse";
        case 467: return "ActivateSessionRequest";
        case 470: response = true; return "ActivateSessionResponse";
        case 473: return "CloseSessionRequest";
        case 476: response = true; return "CloseSessionResponse";
        case 527: return "BrowseRequest";
        case 530: response = true; return "BrowseResponse";
        case 631: return "ReadRequest";
        case 634: response = true; return "ReadResponse";
        case 673: return "WriteRequest";
        case 676: response = true; return "WriteResponse";
        case 787: return "CreateSubscriptionRequest";
        case 790: response = true; return "CreateSubscriptionResponse";
        case 826: return "PublishRequest";
        case 829: response = true; return "PublishResponse";
        case 832: return "RepublishRequest";
        case 835: response = true; return "RepublishResponse";
        case 847: return "DeleteSubscriptionsRequest";
        case 850: response = true; return "DeleteSubscriptionsResponse";
        default: return nullptr;
    }
}

bool IsSecureMessageType(const uint8_t* type) {
    return std::memcmp(type, "OPN", 3) == 0 || std::memcmp(type, "MSG", 3) == 0 || std::memcmp(type, "CLO", 3) == 0 ||
           std::memcmp(type, "ABO", 3) == 0;
}

} // namespace

OPCUA_Analyzer::Reader::Reader(const uint8_t* arg_data, size_t arg_len) : data(arg_data), length(arg_len) {}

bool OPCUA_Analyzer::Reader::Skip(size_t count) {
    if ( ! good || count > Remaining() ) {
        good = false;
        return false;
    }

    position += count;
    return true;
}

bool OPCUA_Analyzer::Reader::U8(uint8_t& value) {
    if ( ! good || Remaining() < 1 ) {
        good = false;
        return false;
    }

    value = data[position++];
    return true;
}

bool OPCUA_Analyzer::Reader::U16(uint16_t& value) {
    if ( ! good || Remaining() < 2 ) {
        good = false;
        return false;
    }

    value = static_cast<uint16_t>(data[position]) | (static_cast<uint16_t>(data[position + 1]) << 8);
    position += 2;
    return true;
}

bool OPCUA_Analyzer::Reader::U32(uint32_t& value) {
    if ( ! good || Remaining() < 4 ) {
        good = false;
        return false;
    }

    value = static_cast<uint32_t>(data[position]) | (static_cast<uint32_t>(data[position + 1]) << 8) |
            (static_cast<uint32_t>(data[position + 2]) << 16) | (static_cast<uint32_t>(data[position + 3]) << 24);
    position += 4;
    return true;
}

bool OPCUA_Analyzer::Reader::I32(int32_t& value) {
    uint32_t raw;
    if ( ! U32(raw) )
        return false;
    value = static_cast<int32_t>(raw);
    return true;
}

bool OPCUA_Analyzer::Reader::U64(uint64_t& value) {
    if ( ! good || Remaining() < 8 ) {
        good = false;
        return false;
    }

    value = 0;
    for ( unsigned i = 0; i < 8; ++i )
        value |= static_cast<uint64_t>(data[position + i]) << (8 * i);
    position += 8;
    return true;
}

bool OPCUA_Analyzer::Reader::F64(double& value) {
    uint64_t raw;
    if ( ! U64(raw) )
        return false;
    static_assert(sizeof(raw) == sizeof(value));
    std::memcpy(&value, &raw, sizeof(value));
    return true;
}

bool OPCUA_Analyzer::Reader::Boolean(bool& value) {
    uint8_t raw;
    if ( ! U8(raw) )
        return false;
    value = raw != 0;
    return true;
}

bool OPCUA_Analyzer::Reader::String(std::string& value, bool allow_null) {
    int32_t len;
    if ( ! I32(len) )
        return false;

    if ( len == -1 && allow_null ) {
        value.clear();
        return true;
    }

    if ( len < 0 || static_cast<size_t>(len) > Remaining() ) {
        good = false;
        return false;
    }

    const size_t captured = std::min(static_cast<size_t>(len), MAX_CAPTURED_STRING);
    value.assign(reinterpret_cast<const char*>(data + position), captured);
    if ( captured < static_cast<size_t>(len) )
        value += "...";

    position += static_cast<size_t>(len);
    return true;
}

bool OPCUA_Analyzer::Reader::ByteString(std::string* value) {
    int32_t len;
    if ( ! I32(len) )
        return false;

    if ( len == -1 ) {
        if ( value )
            value->clear();
        return true;
    }

    if ( len < 0 || static_cast<size_t>(len) > Remaining() ) {
        good = false;
        return false;
    }

    if ( value ) {
        const size_t captured = std::min(static_cast<size_t>(len), MAX_CAPTURED_STRING);
        value->assign(reinterpret_cast<const char*>(data + position), captured);
        if ( captured < static_cast<size_t>(len) )
            *value += "...";
    }

    position += static_cast<size_t>(len);
    return true;
}

bool OPCUA_Analyzer::Reader::NodeId(std::string& value) {
    uint8_t encoding;
    if ( ! U8(encoding) )
        return false;

    const uint8_t node_type = encoding & 0x3f;

    switch ( node_type ) {
        case 0x00: {
            uint8_t id;
            if ( ! U8(id) )
                return false;
            value = "i=" + std::to_string(id);
            return true;
        }

        case 0x01: {
            uint8_t ns;
            uint16_t id;
            if ( ! U8(ns) || ! U16(id) )
                return false;
            value = FormatNodeId(ns, "i", std::to_string(id));
            return true;
        }

        case 0x02: {
            uint16_t ns;
            uint32_t id;
            if ( ! U16(ns) || ! U32(id) )
                return false;
            value = FormatNodeId(ns, "i", std::to_string(id));
            return true;
        }

        case 0x03: {
            uint16_t ns;
            std::string id;
            if ( ! U16(ns) || ! String(id, false) )
                return false;
            value = FormatNodeId(ns, "s", ShortString(id));
            return true;
        }

        case 0x04: {
            uint16_t ns;
            if ( ! U16(ns) || ! Skip(16) )
                return false;
            value = FormatNodeId(ns, "g", "<guid>");
            return true;
        }

        case 0x05: {
            uint16_t ns;
            int32_t len;
            if ( ! U16(ns) || ! I32(len) )
                return false;
            if ( len < -1 || (len >= 0 && static_cast<size_t>(len) > Remaining()) ) {
                good = false;
                return false;
            }
            if ( len > 0 && ! Skip(static_cast<size_t>(len)) )
                return false;
            value = FormatNodeId(ns, "b", len < 0 ? "<null>" : "<" + std::to_string(len) + " bytes>");
            return true;
        }

        default: good = false; return false;
    }
}

bool OPCUA_Analyzer::Reader::ExpandedNodeId(std::string& value) {
    if ( ! good || Remaining() < 1 ) {
        good = false;
        return false;
    }

    const uint8_t flags = data[position];
    if ( ! NodeId(value) )
        return false;

    std::string namespace_uri;
    uint32_t server_index;
    if ( (flags & 0x80) && ! String(namespace_uri) )
        return false;
    if ( (flags & 0x40) && ! U32(server_index) )
        return false;

    return true;
}

bool OPCUA_Analyzer::Reader::QualifiedName() {
    uint16_t ns;
    std::string name;
    return U16(ns) && String(name);
}

bool OPCUA_Analyzer::Reader::LocalizedText() {
    uint8_t mask;
    if ( ! U8(mask) )
        return false;

    std::string text;
    if ( (mask & 0x01) && ! String(text) )
        return false;
    if ( (mask & 0x02) && ! String(text) )
        return false;
    return true;
}

bool OPCUA_Analyzer::Reader::DiagnosticInfo(unsigned depth) {
    if ( depth > MAX_RECURSION ) {
        good = false;
        return false;
    }

    uint8_t mask;
    if ( ! U8(mask) )
        return false;

    if ( (mask & 0x01) && ! Skip(4) )
        return false;
    if ( (mask & 0x02) && ! Skip(4) )
        return false;
    if ( (mask & 0x04) && ! Skip(4) )
        return false;
    if ( (mask & 0x08) && ! Skip(4) )
        return false;

    std::string additional_info;
    if ( (mask & 0x10) && ! String(additional_info) )
        return false;
    if ( (mask & 0x20) && ! Skip(4) )
        return false;
    if ( (mask & 0x40) && ! DiagnosticInfo(depth + 1) )
        return false;

    return true;
}

bool OPCUA_Analyzer::Reader::ExtensionObject(std::string* type_id, unsigned depth) {
    if ( depth > MAX_RECURSION ) {
        good = false;
        return false;
    }

    std::string node_id;
    uint8_t encoding;
    if ( ! NodeId(node_id) || ! U8(encoding) )
        return false;

    if ( type_id )
        *type_id = node_id;

    switch ( encoding ) {
        case 0x00: return true;
        case 0x01:
        case 0x02: {
            int32_t len;
            if ( ! I32(len) )
                return false;
            if ( len < -1 || (len >= 0 && static_cast<size_t>(len) > Remaining()) ) {
                good = false;
                return false;
            }
            return len < 0 || Skip(static_cast<size_t>(len));
        }
        default: good = false; return false;
    }
}

bool OPCUA_Analyzer::Reader::Variant(unsigned depth) {
    if ( depth > MAX_RECURSION ) {
        good = false;
        return false;
    }

    uint8_t encoding;
    if ( ! U8(encoding) )
        return false;

    if ( encoding == 0 )
        return true;

    const uint8_t type = encoding & 0x3f;
    const bool is_array = (encoding & 0x80) != 0;
    const bool has_dimensions = (encoding & 0x40) != 0;

    if ( (! is_array && has_dimensions) || type == 0 || type > 25 ) {
        good = false;
        return false;
    }

    auto skip_scalar = [&](uint8_t scalar_type) -> bool {
        switch ( scalar_type ) {
            case 1:
            case 2:
            case 3: return Skip(1);
            case 4:
            case 5: return Skip(2);
            case 6:
            case 7:
            case 19: return Skip(4);
            case 8:
            case 9:
            case 13: return Skip(8);
            case 10: return Skip(4);
            case 11: return Skip(8);
            case 12:
            case 16: {
                std::string ignored;
                return String(ignored);
            }
            case 14: return Skip(16);
            case 15: return ByteString();
            case 17: {
                std::string ignored;
                return NodeId(ignored);
            }
            case 18: {
                std::string ignored;
                return ExpandedNodeId(ignored);
            }
            case 20: return QualifiedName();
            case 21: return LocalizedText();
            case 22: return ExtensionObject(nullptr, depth + 1);
            case 23: {
                uint32_t ignored_status;
                bool ignored_has_status;
                return DataValue(&ignored_status, &ignored_has_status, depth + 1);
            }
            case 24: return Variant(depth + 1);
            case 25: return DiagnosticInfo(depth + 1);
            default: good = false; return false;
        }
    };

    if ( is_array ) {
        int32_t count;
        if ( ! I32(count) )
            return false;
        if ( count < 0 || static_cast<uint32_t>(count) > MAX_ARRAY_ITEMS ) {
            good = false;
            return false;
        }

        if ( count > 0 && static_cast<size_t>(count) > Remaining() ) {
            good = false;
            return false;
        }

        for ( int32_t i = 0; i < count; ++i ) {
            if ( ! skip_scalar(type) )
                return false;
        }

        if ( has_dimensions ) {
            int32_t dimensions;
            if ( ! I32(dimensions) )
                return false;
            if ( dimensions < 0 || static_cast<uint32_t>(dimensions) > MAX_ARRAY_ITEMS ) {
                good = false;
                return false;
            }
            for ( int32_t i = 0; i < dimensions; ++i ) {
                int32_t dimension;
                if ( ! I32(dimension) )
                    return false;
            }
        }

        return true;
    }

    if ( type == 24 ) {
        good = false;
        return false;
    }

    return skip_scalar(type);
}

bool OPCUA_Analyzer::Reader::DataValue(uint32_t* status, bool* has_status, unsigned depth) {
    if ( depth > MAX_RECURSION ) {
        good = false;
        return false;
    }

    uint8_t mask;
    if ( ! U8(mask) )
        return false;

    if ( mask & 0x01 ) {
        if ( ! Variant(depth + 1) )
            return false;
    }
    if ( mask & 0x02 ) {
        uint32_t value;
        if ( ! U32(value) )
            return false;
        if ( status )
            *status = value;
        if ( has_status )
            *has_status = true;
    }
    if ( mask & 0x04 ) {
        uint64_t timestamp;
        if ( ! U64(timestamp) )
            return false;
    }
    if ( mask & 0x10 ) {
        uint16_t picoseconds;
        if ( ! U16(picoseconds) )
            return false;
    }
    if ( mask & 0x08 ) {
        uint64_t timestamp;
        if ( ! U64(timestamp) )
            return false;
    }
    if ( mask & 0x20 ) {
        uint16_t picoseconds;
        if ( ! U16(picoseconds) )
            return false;
    }

    return true;
}

bool OPCUA_Analyzer::Reader::ArrayLength(uint32_t& count, bool allow_null) {
    int32_t raw;
    if ( ! I32(raw) )
        return false;

    if ( raw == -1 && allow_null ) {
        count = 0;
        return true;
    }

    if ( raw < 0 || static_cast<uint32_t>(raw) > MAX_ARRAY_ITEMS ) {
        good = false;
        return false;
    }

    count = static_cast<uint32_t>(raw);
    return true;
}

OPCUA_Analyzer::OPCUA_Analyzer(Connection* conn) : TCP_ApplicationAnalyzer("OPCUA", conn) {
    max_message_size = BifConst::OPCUA::max_message_size;
    max_node_ids = BifConst::OPCUA::max_node_ids;
    max_extension_objects = BifConst::OPCUA::max_extension_objects;
}

void OPCUA_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    if ( disabled || len <= 0 )
        return;

    DirectionState& state = orig ? orig_state : resp_state;
    if ( state.disabled )
        return;

    if ( state.input.size() - state.input_offset + static_cast<size_t>(len) >
         static_cast<size_t>(max_message_size) + 8 ) {
        SetFailure("OPC UA input exceeds configured max_message_size");
        return;
    }

    state.input.insert(state.input.end(), data, data + len);
    ProcessInput(orig);
}

void OPCUA_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    SetFailure("gap in OPC UA TCP stream");
}

void OPCUA_Analyzer::EndpointEOF(bool is_orig) {
    TCP_ApplicationAnalyzer::EndpointEOF(is_orig);

    DirectionState& state = is_orig ? orig_state : resp_state;
    if ( state.assembling ) {
        SetFailure("truncated OPC UA message at end of stream");
        state.assembling = false;
        state.chunk_data.clear();
    }
}

void OPCUA_Analyzer::SetFailure(const char* reason) {
    if ( ! disabled )
        AnalyzerViolation(reason);

    disabled = true;
    orig_state.disabled = true;
    resp_state.disabled = true;
}

void OPCUA_Analyzer::Compact(DirectionState& state) {
    if ( state.input_offset == state.input.size() ) {
        state.input.clear();
        state.input_offset = 0;
    }
    else if ( state.input_offset > 65536 ) {
        state.input.erase(state.input.begin(), state.input.begin() + state.input_offset);
        state.input_offset = 0;
    }
}

void OPCUA_Analyzer::ProcessInput(bool orig) {
    DirectionState& state = orig ? orig_state : resp_state;

    while ( ! state.disabled && state.input.size() - state.input_offset >= 8 ) {
        const uint8_t* message = state.input.data() + state.input_offset;
        const size_t available = state.input.size() - state.input_offset;

        uint32_t message_size = static_cast<uint32_t>(message[4]) | (static_cast<uint32_t>(message[5]) << 8) |
                                (static_cast<uint32_t>(message[6]) << 16) | (static_cast<uint32_t>(message[7]) << 24);

        if ( message_size < 8 || message_size > max_message_size ) {
            SetFailure("invalid OPC UA message chunk size");
            return;
        }

        if ( available < message_size )
            break;

        const bool ok = ProcessChunk(state, message, message_size, orig);
        state.input_offset += message_size;
        Compact(state);

        if ( ! ok )
            return;
    }

    Compact(state);
}

bool OPCUA_Analyzer::ProcessChunk(DirectionState& state, const uint8_t* data, size_t len, bool orig) {
    const uint8_t* type = data;
    const uint8_t chunk_type = data[3];

    if ( std::memcmp(type, "HEL", 3) == 0 || std::memcmp(type, "ACK", 3) == 0 )
        return ProcessHello(state, type, len, orig);

    if ( ! IsSecureMessageType(type) ) {
        SetFailure("unknown OPC UA message type");
        return false;
    }

    if ( chunk_type != 'C' && chunk_type != 'F' ) {
        SetFailure("invalid OPC UA chunk type");
        return false;
    }

    return ProcessSecureChunk(state, type, data, len, orig);
}

bool OPCUA_Analyzer::ProcessHello(DirectionState& state, const uint8_t* type, size_t len, bool orig) {
    if ( type[3] != 'F' || len < 8 ) {
        SetFailure("invalid OPC UA Hello/Acknowledge message");
        return false;
    }

    MessageInfo info;
    info.message_type.assign(reinterpret_cast<const char*>(type), 3);
    info.service = info.message_type == "HEL" ? "Hello" : "Acknowledge";
    info.chunk_count = 1;
    info.message_size = static_cast<uint32_t>(len);

    Reader reader(type + 8, len - 8);
    uint32_t value;
    std::string endpoint_url;

    if ( ! reader.U32(value) ) {
        SetFailure("truncated OPC UA Hello/Acknowledge message");
        return false;
    }

    if ( info.message_type == "HEL" ) {
        if ( ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) ||
             ! reader.String(endpoint_url, false) ) {
            SetFailure("truncated OPC UA Hello message");
            return false;
        }
        info.endpoint = endpoint_url;
    }
    else if ( ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) ) {
        SetFailure("truncated OPC UA Acknowledge message");
        return false;
    }

    if ( ! saw_protocol ) {
        saw_protocol = true;
        AnalyzerConfirmation();
    }

    Emit(info, orig);
    return true;
}

bool OPCUA_Analyzer::ProcessSecureChunk(DirectionState& state, const uint8_t* type, const uint8_t* data, size_t len,
                                        bool orig) {
    const uint8_t chunk_type = type[3];
    const std::string message_type(reinterpret_cast<const char*>(type), 3);

    Reader reader(data + 8, len - 8);
    uint32_t channel_id;
    if ( ! reader.U32(channel_id) ) {
        SetFailure("truncated OPC UA secure-channel message");
        return false;
    }

    if ( message_type == "ABO" ) {
        MessageInfo info;
        info.message_type = message_type;
        info.service = "Abort";
        info.chunk_type = std::string(1, static_cast<char>(chunk_type));
        info.chunk_count = 1;
        info.message_size = static_cast<uint32_t>(len);

        uint32_t error;
        std::string reason;
        if ( reader.U32(error) ) {
            info.status = error;
            info.has_status = true;
            reader.String(reason);
        }

        Emit(info, orig);
        return true;
    }

    std::string policy_id;
    if ( ! reader.String(policy_id) ) {
        SetFailure("truncated OPC UA security header");
        return false;
    }

    if ( ! reader.ByteString() || ! reader.ByteString() ) {
        SetFailure("truncated OPC UA security header");
        return false;
    }

    uint32_t sequence_number;
    uint32_t request_id;
    if ( ! reader.U32(sequence_number) || ! reader.U32(request_id) ) {
        SetFailure("truncated OPC UA sequence header");
        return false;
    }

    if ( ! state.assembling ) {
        state.assembling = true;
        state.chunk_message_type = message_type;
        state.chunk_type = std::string(1, static_cast<char>(chunk_type));
        state.chunk_request_id = request_id;
        state.chunk_count = 0;
        state.chunk_data.clear();
        state.security_policy = policy_id;
    }
    else if ( state.chunk_message_type != message_type || state.chunk_request_id != request_id ) {
        SetFailure("inconsistent OPC UA message chunk");
        return false;
    }

    const size_t remaining = reader.Remaining();
    if ( remaining > max_message_size || state.chunk_data.size() + remaining > max_message_size ) {
        SetFailure("OPC UA reassembled message exceeds configured max_message_size");
        return false;
    }

    if ( remaining > 0 )
        state.chunk_data.insert(state.chunk_data.end(), reader.Current(), reader.Current() + remaining);

    if ( state.chunk_count >= MAX_CHUNKS ) {
        SetFailure("too many OPC UA message chunks");
        return false;
    }

    ++state.chunk_count;
    state.last_message_size = static_cast<uint32_t>(len);

    if ( chunk_type == 'C' )
        return true;

    if ( ! FinishMessage(state, orig) )
        return false;

    state.assembling = false;
    state.chunk_data.clear();
    state.chunk_count = 0;
    state.chunk_message_type.clear();
    state.chunk_type.clear();
    return true;
}

bool OPCUA_Analyzer::FinishMessage(DirectionState& state, bool orig) {
    MessageInfo info;
    info.message_type = state.chunk_message_type;
    info.request_id = state.chunk_request_id;
    info.chunk_type = state.chunk_type;
    info.chunk_count = state.chunk_count;
    info.message_size = state.chunk_data.size();
    info.security_policy = state.security_policy;

    Reader reader(state.chunk_data.data(), state.chunk_data.size());

    const size_t payload_len = state.chunk_data.size();
    const bool clear_text_policy =
        state.security_policy.empty() || state.security_policy.find("#None") != std::string::npos;

    if ( info.message_type == "MSG" && ! clear_text_policy && security_mode == "SignAndEncrypt" ) {
        info.service = "Encrypted";
        info.message_size = state.last_message_size;
        Emit(info, orig);
        return true;
    }

    if ( payload_len == 0 ) {
        info.service = "Empty";
        Emit(info, orig);
        return true;
    }

    bool response = false;
    if ( ! ParseServicePayload(info, reader, orig, response) ) {
        info.message_size = state.last_message_size;

        if ( ! clear_text_policy && (info.message_type == "MSG" || info.message_type == "OPN") )
            info.service = "Encrypted";
        else {
            info.service = "Unparsed";
            Weird("opcua_service_decode_failed", info.message_type.c_str());
        }

        Emit(info, orig);
        return true;
    }

    info.message_size = state.last_message_size;

    if ( response ) {
        auto pending = pending_requests.find(info.request_id);
        if ( pending != pending_requests.end() ) {
            info.node_ids = pending->second.node_ids;
            pending_requests.erase(pending);
        }
    }

    if ( ! saw_protocol ) {
        saw_protocol = true;
        AnalyzerConfirmation();
    }

    Emit(info, orig);
    return true;
}

bool OPCUA_Analyzer::ParseServicePayload(MessageInfo& info, Reader& reader, bool orig, bool& response) {
    std::string service_node;
    if ( ! reader.NodeId(service_node) )
        return false;

    uint32_t id = 0;
    const auto semicolon = service_node.rfind('=');
    if ( semicolon == std::string::npos )
        return false;

    try {
        id = static_cast<uint32_t>(std::stoul(service_node.substr(semicolon + 1)));
    } catch ( const std::exception& ) {
        return false;
    }

    const char* name = ServiceName(id, response);
    if ( ! name ) {
        info.service = "Unknown(" + service_node + ")";
        return true;
    }

    info.service = name;

    bool parsed = true;
    switch ( id ) {
        case 397: parsed = ParseResponseHeader(reader, info); break;
        case 428:
        case 431: parsed = ParseGetEndpoints(info, reader, response); break;
        case 446:
        case 449: parsed = ParseOpenSecureChannel(info, reader, response); break;
        case 452:
        case 455: parsed = response ? ParseResponseHeader(reader, info) : ParseRequestHeader(reader); break;
        case 461:
        case 464: parsed = ParseCreateSession(info, reader, response); break;
        case 631:
        case 634: parsed = ParseRead(info, reader, response); break;
        case 673:
        case 676: parsed = ParseWrite(info, reader, response); break;
        case 787:
        case 790: parsed = ParseCreateSubscription(info, reader, response); break;
        case 826:
        case 829: parsed = ParsePublish(info, reader, response); break;
        default: parsed = response ? ParseResponseHeader(reader, info) : ParseRequestHeader(reader); break;
    }

    if ( ! parsed )
        return false;

    if ( ! response ) {
        PendingRequest pending;
        pending.node_ids = info.node_ids;

        if ( pending_requests.size() >= MAX_PENDING_REQUESTS )
            pending_requests.erase(pending_requests.begin());
        pending_requests[info.request_id] = std::move(pending);
    }

    return true;
}

bool OPCUA_Analyzer::ParseRequestHeader(Reader& reader, std::string* auth_token) {
    std::string token;
    uint64_t timestamp;
    uint32_t value;
    std::string audit_entry;

    if ( ! reader.NodeId(token) || ! reader.U64(timestamp) || ! reader.U32(value) || ! reader.U32(value) ||
         ! reader.String(audit_entry) || ! reader.U32(value) || ! reader.ExtensionObject(nullptr) )
        return false;

    if ( auth_token )
        *auth_token = token;

    return true;
}

bool OPCUA_Analyzer::ParseResponseHeader(Reader& reader, MessageInfo& info) {
    uint64_t timestamp;
    uint32_t request_handle;
    uint32_t service_result;
    uint32_t string_table_count;

    if ( ! reader.U64(timestamp) || ! reader.U32(request_handle) || ! reader.U32(service_result) ||
         ! reader.DiagnosticInfo() || ! reader.ArrayLength(string_table_count) )
        return false;

    for ( uint32_t i = 0; i < string_table_count; ++i ) {
        std::string value;
        if ( ! reader.String(value) )
            return false;
    }

    std::string extension_type;
    if ( ! reader.ExtensionObject(&extension_type) )
        return false;
    if ( ! extension_type.empty() && extension_type != "i=0" )
        AddExtensionObject(info, extension_type);

    info.status = service_result;
    info.has_status = true;
    return true;
}

bool OPCUA_Analyzer::ParseApplicationDescription(Reader& reader) {
    std::string value;
    uint32_t count;

    if ( ! reader.String(value) || ! reader.String(value) || ! reader.LocalizedText() || ! reader.U32(count) ||
         ! reader.String(value) || ! reader.String(value) || ! reader.ArrayLength(count) )
        return false;

    for ( uint32_t i = 0; i < count; ++i ) {
        if ( ! reader.String(value) )
            return false;
    }

    return true;
}

bool OPCUA_Analyzer::ParseEndpointDescription(Reader& reader, std::string& endpoint_url, std::string& policy,
                                              std::string& mode) {
    uint32_t count;
    uint32_t security_mode_value;
    uint8_t security_level;

    if ( ! reader.String(endpoint_url) || ! ParseApplicationDescription(reader) || ! reader.ByteString() ||
         ! reader.U32(security_mode_value) || ! reader.String(policy) || ! reader.ArrayLength(count) )
        return false;

    for ( uint32_t i = 0; i < count; ++i ) {
        std::string value;
        uint32_t token_type;
        if ( ! reader.String(value) || ! reader.U32(token_type) || ! reader.String(value) || ! reader.String(value) ||
             ! reader.String(value) )
            return false;
    }

    std::string transport_profile;
    if ( ! reader.String(transport_profile) || ! reader.U8(security_level) )
        return false;

    mode = SecurityModeName(security_mode_value);
    return true;
}

bool OPCUA_Analyzer::ParseEndpointDescriptions(Reader& reader, uint32_t count, std::string& endpoint_url,
                                               std::string& policy, std::string& mode) {
    if ( count > 64 ) {
        reader.Skip(reader.Remaining());
        return true;
    }

    for ( uint32_t i = 0; i < count; ++i ) {
        std::string current_endpoint;
        std::string current_policy;
        std::string current_mode;
        if ( ! ParseEndpointDescription(reader, current_endpoint, current_policy, current_mode) )
            return false;

        if ( i == 0 ) {
            endpoint_url = current_endpoint;
            policy = current_policy;
            mode = current_mode;
        }
    }

    return true;
}

bool OPCUA_Analyzer::ParseOpenSecureChannel(MessageInfo& info, Reader& reader, bool response) {
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) )
            return false;

        uint32_t value;
        uint64_t created_at;
        uint32_t revised_lifetime;
        if ( ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) || ! reader.U64(created_at) ||
             ! reader.U32(revised_lifetime) || ! reader.ByteString() )
            return false;
    }
    else {
        std::string auth_token;
        if ( ! ParseRequestHeader(reader, &auth_token) )
            return false;

        uint32_t client_protocol_version;
        uint32_t request_type;
        uint32_t mode;
        uint32_t requested_lifetime;
        if ( ! reader.U32(client_protocol_version) || ! reader.U32(request_type) || ! reader.U32(mode) ||
             ! reader.ByteString() || ! reader.U32(requested_lifetime) )
            return false;

        info.security_mode = SecurityModeName(mode);
    }

    return true;
}

bool OPCUA_Analyzer::ParseGetEndpoints(MessageInfo& info, Reader& reader, bool response) {
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) )
            return false;

        uint32_t count;
        if ( ! reader.ArrayLength(count) )
            return false;

        std::string endpoint_url;
        std::string policy;
        std::string mode;
        if ( ! ParseEndpointDescriptions(reader, count, endpoint_url, policy, mode) )
            return false;

        info.endpoint = endpoint_url;
        info.security_policy = policy;
        info.security_mode = mode;
    }
    else {
        if ( ! ParseRequestHeader(reader) )
            return false;

        std::string endpoint_url;
        uint32_t count;
        std::string value;

        if ( ! reader.String(endpoint_url, false) || ! reader.ArrayLength(count) )
            return false;
        for ( uint32_t i = 0; i < count; ++i ) {
            if ( ! reader.String(value) )
                return false;
        }
        if ( ! reader.ArrayLength(count) )
            return false;
        for ( uint32_t i = 0; i < count; ++i ) {
            if ( ! reader.String(value) )
                return false;
        }

        info.endpoint = endpoint_url;
    }

    return true;
}

bool OPCUA_Analyzer::ParseCreateSession(MessageInfo& info, Reader& reader, bool response) {
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) )
            return false;

        std::string session_node;
        std::string auth_node;
        double revised_timeout;
        uint32_t count;
        uint32_t value;

        if ( ! reader.NodeId(session_node) || ! reader.NodeId(auth_node) || ! reader.F64(revised_timeout) ||
             ! reader.ByteString() || ! reader.ByteString() || ! reader.ArrayLength(count) )
            return false;

        std::string endpoint_url;
        std::string policy;
        std::string mode;
        if ( ! ParseEndpointDescriptions(reader, count, endpoint_url, policy, mode) )
            return false;

        if ( ! reader.ArrayLength(count) )
            return false;
        for ( uint32_t i = 0; i < count; ++i ) {
            if ( ! reader.ByteString() || ! reader.ByteString() )
                return false;
        }

        std::string algorithm;
        if ( ! reader.String(algorithm) || ! reader.ByteString() || ! reader.U32(value) )
            return false;

        info.session_id = session_node;
        if ( ! endpoint_url.empty() )
            info.endpoint = endpoint_url;
        if ( ! policy.empty() )
            info.security_policy = policy;
        if ( ! mode.empty() )
            info.security_mode = mode;
    }
    else {
        std::string auth_token;
        if ( ! ParseRequestHeader(reader, &auth_token) )
            return false;

        if ( ! ParseApplicationDescription(reader) )
            return false;

        std::string server_uri;
        std::string endpoint_url;
        std::string session_name;
        double requested_timeout;
        uint32_t max_response_size;

        if ( ! reader.String(server_uri) || ! reader.String(endpoint_url) || ! reader.String(session_name) ||
             ! reader.ByteString() || ! reader.ByteString() || ! reader.F64(requested_timeout) ||
             ! reader.U32(max_response_size) )
            return false;

        info.endpoint = endpoint_url;
    }

    return true;
}

bool OPCUA_Analyzer::ParseRead(MessageInfo& info, Reader& reader, bool response) {
    double max_age;
    uint32_t timestamps;
    uint32_t count;

    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) || ! reader.ArrayLength(count) )
            return false;

        bool first_status = true;
        for ( uint32_t i = 0; i < count; ++i ) {
            uint32_t status = 0;
            bool has_status = false;
            if ( ! reader.DataValue(&status, &has_status) )
                return false;

            if ( has_status && (first_status || status != 0) && (! info.has_status || info.status == 0) ) {
                info.status = status;
                info.has_status = true;
                first_status = false;
            }
        }
    }
    else {
        if ( ! ParseRequestHeader(reader) )
            return false;

        if ( ! reader.F64(max_age) || ! reader.U32(timestamps) || ! reader.ArrayLength(count) )
            return false;

        for ( uint32_t i = 0; i < count; ++i ) {
            std::string node_id;
            uint32_t attribute;
            std::string index_range;
            if ( ! reader.NodeId(node_id) || ! reader.U32(attribute) || ! reader.String(index_range) ||
                 ! reader.QualifiedName() )
                return false;
            AddNodeId(info, node_id);
        }
    }

    return true;
}

bool OPCUA_Analyzer::ParseWrite(MessageInfo& info, Reader& reader, bool response) {
    uint32_t count;
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) || ! reader.ArrayLength(count) )
            return false;

        for ( uint32_t i = 0; i < count; ++i ) {
            uint32_t status;
            if ( ! reader.U32(status) )
                return false;
            if ( status != 0 || ! info.has_status || info.status == 0 ) {
                info.status = status;
                info.has_status = true;
            }
        }
    }
    else {
        if ( ! ParseRequestHeader(reader) )
            return false;

        if ( ! reader.ArrayLength(count) )
            return false;

        for ( uint32_t i = 0; i < count; ++i ) {
            std::string node_id;
            uint32_t attribute;
            std::string index_range;
            uint32_t ignored_status;
            bool ignored_has_status;

            if ( ! reader.NodeId(node_id) || ! reader.U32(attribute) || ! reader.String(index_range) ||
                 ! reader.DataValue(&ignored_status, &ignored_has_status) )
                return false;
            AddNodeId(info, node_id);
        }
    }

    return true;
}

bool OPCUA_Analyzer::ParseCreateSubscription(MessageInfo& info, Reader& reader, bool response) {
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) )
            return false;

        uint32_t id;
        double interval;
        uint32_t lifetime;
        uint32_t keep_alive;
        if ( ! reader.U32(id) || ! reader.F64(interval) || ! reader.U32(lifetime) || ! reader.U32(keep_alive) )
            return false;

        info.subscription_id = id;
        info.has_subscription = true;
    }
    else {
        if ( ! ParseRequestHeader(reader) )
            return false;

        double interval;
        uint32_t value;
        bool publishing_enabled;
        uint8_t priority;
        if ( ! reader.F64(interval) || ! reader.U32(value) || ! reader.U32(value) || ! reader.U32(value) ||
             ! reader.Boolean(publishing_enabled) || ! reader.U8(priority) )
            return false;
    }

    return true;
}

bool OPCUA_Analyzer::ParsePublish(MessageInfo& info, Reader& reader, bool response) {
    uint32_t count;
    if ( response ) {
        if ( ! ParseResponseHeader(reader, info) )
            return false;

        uint32_t id;
        uint32_t sequence_count;
        bool more_notifications;
        uint32_t sequence_number;
        uint64_t publish_time;
        uint32_t notification_count;
        uint32_t result_count;
        uint32_t diagnostic_count;

        if ( ! reader.U32(id) || ! reader.ArrayLength(sequence_count) )
            return false;
        for ( uint32_t i = 0; i < sequence_count; ++i ) {
            uint32_t ignored;
            if ( ! reader.U32(ignored) )
                return false;
        }

        if ( ! reader.Boolean(more_notifications) || ! reader.U32(sequence_number) || ! reader.U64(publish_time) ||
             ! reader.ArrayLength(notification_count) )
            return false;

        for ( uint32_t i = 0; i < notification_count; ++i ) {
            std::string extension_type;
            if ( ! reader.ExtensionObject(&extension_type) )
                return false;
            if ( ! extension_type.empty() && extension_type != "i=0" )
                AddExtensionObject(info, extension_type);
        }

        if ( ! reader.ArrayLength(result_count) )
            return false;
        for ( uint32_t i = 0; i < result_count; ++i ) {
            uint32_t status;
            if ( ! reader.U32(status) )
                return false;
            if ( status != 0 || ! info.has_status || info.status == 0 ) {
                info.status = status;
                info.has_status = true;
            }
        }

        if ( ! reader.ArrayLength(diagnostic_count) )
            return false;
        for ( uint32_t i = 0; i < diagnostic_count; ++i ) {
            if ( ! reader.DiagnosticInfo() )
                return false;
        }

        info.subscription_id = id;
        info.has_subscription = true;
    }
    else {
        if ( ! ParseRequestHeader(reader) )
            return false;

        if ( ! reader.ArrayLength(count) )
            return false;

        for ( uint32_t i = 0; i < count; ++i ) {
            uint32_t subscription;
            uint32_t sequence;
            if ( ! reader.U32(subscription) || ! reader.U32(sequence) )
                return false;
            if ( i == 0 ) {
                info.subscription_id = subscription;
                info.has_subscription = true;
            }
        }
    }

    return true;
}

void OPCUA_Analyzer::AddNodeId(MessageInfo& info, const std::string& node_id) {
    if ( node_id.empty() || node_id == "i=0" )
        return;
    if ( info.node_ids.size() >= max_node_ids )
        return;
    if ( std::find(info.node_ids.begin(), info.node_ids.end(), node_id) == info.node_ids.end() )
        info.node_ids.push_back(node_id);
}

void OPCUA_Analyzer::AddExtensionObject(MessageInfo& info, const std::string& type_id) {
    if ( type_id.empty() || info.extension_objects.size() >= max_extension_objects )
        return;
    if ( std::find(info.extension_objects.begin(), info.extension_objects.end(), type_id) ==
         info.extension_objects.end() )
        info.extension_objects.push_back(type_id);
}

void OPCUA_Analyzer::UpdateContext(const MessageInfo& info) {
    if ( ! info.endpoint.empty() )
        endpoint = ShortString(info.endpoint);
    if ( ! info.security_policy.empty() )
        security_policy = ShortString(info.security_policy);
    if ( ! info.security_mode.empty() && info.security_mode != "Invalid" )
        security_mode = info.security_mode;
    if ( ! info.session_id.empty() )
        session_id = info.session_id;
}

void OPCUA_Analyzer::Emit(MessageInfo& info, bool orig) {
    UpdateContext(info);

    if ( info.endpoint.empty() )
        info.endpoint = endpoint;
    if ( info.security_policy.empty() )
        info.security_policy = security_policy;
    if ( info.security_mode.empty() )
        info.security_mode = security_mode.empty() ? "None" : security_mode;
    if ( info.session_id.empty() )
        info.session_id = session_id;
    auto nodes = make_intrusive<VectorVal>(id::string_vec);
    for ( const auto& node_id : info.node_ids )
        nodes->Append(make_intrusive<StringVal>(node_id));

    auto extensions = make_intrusive<VectorVal>(id::string_vec);
    for ( const auto& extension : info.extension_objects )
        extensions->Append(make_intrusive<StringVal>(extension));

    EnqueueConnEvent(opcua_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(info.message_type),
                     make_intrusive<StringVal>(info.service), make_intrusive<StringVal>(ShortString(info.endpoint)),
                     make_intrusive<StringVal>(ShortString(info.security_policy)),
                     make_intrusive<StringVal>(info.security_mode), val_mgr->Count(info.status),
                     val_mgr->Bool(info.has_status), make_intrusive<StringVal>(info.session_id),
                     val_mgr->Count(info.subscription_id), val_mgr->Bool(info.has_subscription),
                     val_mgr->Count(info.request_id),
                     make_intrusive<StringVal>(info.chunk_type.empty() ? "F" : info.chunk_type),
                     val_mgr->Count(info.chunk_count), val_mgr->Count(info.message_size), std::move(nodes),
                     std::move(extensions));
}

} // namespace zeek::analyzer::opcua
