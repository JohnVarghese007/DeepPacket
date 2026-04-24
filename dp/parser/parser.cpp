#include "parser.hpp"

namespace dp::parser {

// Parser entry point
ParsedPacket parse_packet(std::span<const uint8_t> buffer) {
    return ParsedPacket(buffer);
}

} // namespace dp::parser
