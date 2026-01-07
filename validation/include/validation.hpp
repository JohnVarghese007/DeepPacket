#pragma once
#include "packet_view.hpp"
#include "packet-error.hpp"
#include <vector>

std::vector<ValidationError> validate_packet(const PacketView& view);

bool validate_ethernet(const PacketView& view);
bool validate_ipv4(const PacketView& view);
bool validate_tcp(const PacketView& view);
bool validate_udp(const PacketView& view);