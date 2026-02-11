#pragma  once
#include "layers.hpp"
#include <cstddef>
#include <cstdint>

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
    
    EthernetLayer eth_layer;
    ARPLayer arp_layer;
    IPv4Layer ip_layer;
    TCPLayer tcp_layer;
    UDPLayer udp_layer;
    ICMPLayer icmp_layer;
    const uint8_t* payload;
    size_t payload_len;

    // Supported Layer 4 Protocols
    L4Type l4_type;

    // PacketView Constructor
    PacketView(const uint8_t* packet, size_t length);


    // Print Packet Details
    void print(std::ostream& os) const;

    // Get Packet Size
    size_t size() const { return length; }

    
private:
    void parse_layers();
};