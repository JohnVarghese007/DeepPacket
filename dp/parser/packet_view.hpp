#pragma  once
#include "dp/parser/layers.hpp"
#include <cstddef>
#include <cstdint>


namespace dp {
namespace parser {

class PacketView {
public:

    // Raw Packet Data
    const uint8_t* data;
    size_t length;

    // Layer Presence Flags
    bool has_eth;
    bool has_arp;
    bool has_ip;
    bool has_tcp;
    bool has_udp;
    bool has_icmp;
    
    layers::EthernetLayer eth_layer;
    layers::ARPLayer arp_layer;
    layers::IPv4Layer ip_layer;
    layers::TCPLayer tcp_layer;
    layers::UDPLayer udp_layer;
    layers::ICMPLayer icmp_layer;
    const uint8_t* payload;
    size_t payload_len;

    // Supported Layer 4 Protocols
    L4Type l4_type;

    // PacketView Constructor
    PacketView(const uint8_t* packet, size_t length);


    // Print Packet Details
    void print(std::ostream& os) const;

    // String representation of packet view (for CLI output)
    std::string to_string() const;

    // Get Packet Size
    size_t size() const { return length; }

    // Live capture flag
    bool is_live_capture = false;

    
private:
    void parse_layers();
};


} // namespace parser
} // namespace dp
