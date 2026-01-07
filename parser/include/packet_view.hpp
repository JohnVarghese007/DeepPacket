#pragma  once
#include "layers.hpp"
#include <cstddef>
#include <cstdint>

class PacketView {
public:
    EthernetLayer* eth_layer;
    IPv4Layer* ip_layer;
    TCPLayer* tcp_layer;
    UDPLayer* udp_layer;
    const uint8_t* payload;
    size_t payload_len;

    // Supported Layer 4 Protocols
    L4Type l4_type;

    // PacketView Constructor
    PacketView(const uint8_t* packet);

    // PacketView Destructor
    ~PacketView();

    // Print Packet Details
    void print() const;

    
// CAN BE IGNORED FOR NOW
private:
    static bool validate_layer_sizes(const uint8_t* packet, size_t size);
};