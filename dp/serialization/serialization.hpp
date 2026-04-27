#pragma once

#include <string>
#include <nlohmann/json.hpp>

#include "dp/parser/packet_view.hpp"
#include "dp/validation/validation.hpp"


namespace dp {
namespace serialization {

/**
 * Convert a parsed + validated packet into JSON for the GUI.
 * Fully supports:
 *  - Ethernet
 *  - ARP
 *  - IPv4
 *  - IPv6
 *  - TCP
 *  - UDP
 *  - ICMPv4
 *  - ICMPv6
 */
nlohmann::json packet_to_json(dp::parser::PacketView& view,  dp::validation::PacketValidator& validator);

/**
 * Convert packet to pretty‑printed JSON string.
 * - wrapper on packet_to_json
 */
std::string packet_to_json_string(dp::parser::PacketView& view, dp::validation::PacketValidator& validator);

}  // namespace serialization
} // namespace dp