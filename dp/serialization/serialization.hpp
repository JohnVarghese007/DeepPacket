#pragma once

#include <string>
#include <nlohmann/json.hpp>

#include "dp/parser/packet_view.hpp"
#include "dp/validation/validation.hpp"


namespace dp {
namespace serialization {

// Convert a parsed + validated packet into JSON for the GUI
nlohmann::json packet_to_json(dp::parser::PacketView& view,  dp::validation::PacketValidator& validator);

// JSON string with indentation
std::string packet_to_json_string(dp::parser::PacketView& view, dp::validation::PacketValidator& validator);

}  // namespace serialization
} // namespace dp