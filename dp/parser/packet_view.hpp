#pragma  once
#include "dp/parser/layers.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <ostream>


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
    bool has_ipv4;
    bool has_ipv6;
    bool has_tcp;
    bool has_udp;
    bool has_icmpv4;
    bool has_icmpv6;
    
    layers::EthernetLayer eth_layer;
    layers::ARPLayer arp_layer;
    layers::IPv4Layer ipv4_layer;
    layers::IPv6Layer ipv6_layer;
    layers::TCPLayer tcp_layer;
    layers::UDPLayer udp_layer;
    layers::ICMPv4Layer icmpv4_layer;
    layers::ICMPv6Layer icmpv6_layer;
    const uint8_t* payload;
    size_t payload_len;

    // Next protocol inside IPv4/IPv6 (TCP, UDP, ICMPv4, ICMPv6 or UNKNOWN)
    IpProto ip_proto;

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
