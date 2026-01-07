#include "parser.hpp"

// Parser API Entry Point
ParsedPacket parse_packet(std::span<const uint8_t> buffer) {
    return ParsedPacket(buffer.data());
}
