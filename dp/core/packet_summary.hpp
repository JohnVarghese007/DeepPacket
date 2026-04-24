#pragma once

#include <cstdint>
#include <string>
#include <chrono>


namespace dp {
namespace core {

enum class TransportProtocol {
    UNKNOWN = 0,
    TCP,
    UDP,
    ICMP,
    ARP
};

enum class ValidationStatus {
    OK = 0,
    ERROR
};

struct PacketSummary {
    std::chrono::microseconds timestamp{0};
    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;

    // IPv4 addresses 
    std::string src_ip;
    std::string dst_ip;

    // Ports (0 if not applicable)
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // Protocol classification
    TransportProtocol protocol = TransportProtocol::UNKNOWN;

    // Packet length
    uint32_t length = 0;

    // Validation result
    ValidationStatus validation = ValidationStatus::OK;

    // Optional: TCP flags (0 for non‑TCP)
    uint8_t tcp_flags = 0;
};

inline const char* transport_proto_to_string(TransportProtocol proto) {
    switch (proto) {
        case TransportProtocol::TCP:   return "TCP";
        case TransportProtocol::UDP:   return "UDP";
        case TransportProtocol::ICMP:  return "ICMP";
        case TransportProtocol::ARP:   return "ARP";
        default:                       return "UNKNOWN";
    }
}

} // namespace core
} // namespace dp