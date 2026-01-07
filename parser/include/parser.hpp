#pragma once
#include <span>
#include <cstdint>
#include "packet_view.hpp"

class ParsedPacket {
public:
    PacketView view;

    ParsedPacket(const uint8_t* data)
        : view(data) {}
};

// Main parser API.
ParsedPacket parse_packet(std::span<const uint8_t> buffer);
