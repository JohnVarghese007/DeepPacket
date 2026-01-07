#pragma once
#include <span>
#include <cstdint>
#include "packet_view.hpp"

// ParsedPacket is a lightweight wrapper around PacketView.
// Later you can expand this to include:
// - protocol detection
// - parsed header structs
// - offsets
// - validation results
class ParsedPacket {
public:
    PacketView view;

    ParsedPacket(const uint8_t* data)
        : view(data) {}
};

// Main parser API.
// Takes raw bytes and returns a structured ParsedPacket.
ParsedPacket parse_packet(std::span<const uint8_t> buffer);
