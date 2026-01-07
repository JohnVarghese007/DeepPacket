#pragma once
#include <span>
#include <cstdint>
#include "packet_view.hpp"

struct ParsedPacket {
public:
    std::span<const uint8_t> buffer;
    PacketView view;

    ParsedPacket(std::span<const uint8_t> buf)
        : buffer(buf), view(buf.data(), buf.size()) {}
};

// Main parser API.
ParsedPacket parse_packet(std::span<const uint8_t> buffer);
