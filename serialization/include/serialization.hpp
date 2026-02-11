#pragma once

#include <string>
#include <nlohmann/json.hpp>

#include "packet_view.hpp"
#include "validation.hpp"

// Convert a parsed + validated packet into JSON for the GUI
nlohmann::json packet_to_json(PacketView& view,  PacketValidator& validator);

// JSON string with indentation
std::string packet_to_json_string(PacketView& view, PacketValidator& validator);