#pragma once

#include <cstdint>
#include <string>
#include <chrono>

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