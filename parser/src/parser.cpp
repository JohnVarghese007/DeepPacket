#include "parser.hpp"

// Parser entry point
ParsedPacket parse_packet(std::span<const uint8_t> buffer) {
    return ParsedPacket(buffer.data());
}
