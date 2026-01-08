#include "packet_view.hpp"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

#define TCP_PROTOCOL_VALUE 6
#define UDP_PROTOCOL_VALUE 17
#define IPv4_ETHERTYPE 0x0800
#define MINIMUM_TCP_HEADER_SIZE 20
#define MINIMUM_UDP_HEADER_SIZE 8

/*
    PacketView Class Implementation
    - This class provides a structural view of a raw network packet
    - parses raw byte buffer into supported protocol layers (Ethernet, IPv4, TCP, UDP)
    - Does not handle validation -> that is to be done separately by the validation module
*/

// PacketView Constructor
PacketView::PacketView(const uint8_t* packet, size_t length) :
    data(packet), length(length), 
    has_eth(false), has_ip(false), has_tcp(false), has_udp(false),
    payload(nullptr), payload_len(0), l4_type(L4Type::UNKNOWN)
{
    parse_layers();
}

// Parse Layers
void PacketView::parse_layers() {

    // Ethernet Layer
    if (length < sizeof(EthernetHeader)) {
        return; 
    }
    eth_layer = EthernetLayer(data);
    has_eth = true;

    // EtherType check for IPv4
    uint16_t ethertype = ntohs(eth_layer.eth->ether_type);
    if (ethertype != IPv4_ETHERTYPE) {
        return; 
    }

    // IPv4 Layer
    size_t ip_offset = sizeof(EthernetHeader);
    if (length < ip_offset + 1) {
        return;
    }
    ip_layer = IPv4Layer(data + ip_offset);
    has_ip = true;

    // Looking at ihl bits to determine IPv4 header size
    size_t ihl = (ip_layer.iph->version_ihl & 0x0F) * 4;

    // Adding ihl to ip_offset to point to L4 header
    size_t l4_offset = ip_offset + ihl;    

    // Determining Layer 4 Protocol
    if(ip_layer.iph->protocol == TCP_PROTOCOL_VALUE) {
        l4_type = L4Type::TCP;
        if (length < l4_offset + 1) {
            return;
        }
        tcp_layer = TCPLayer(data + l4_offset);
        has_tcp = true;
        payload = (l4_offset < length) ? data + l4_offset : nullptr;
        payload_len = (l4_offset < length) ? (length - l4_offset) : 0;        
        return;
    }
    else if(ip_layer.iph->protocol == UDP_PROTOCOL_VALUE) {
        l4_type = L4Type::UDP;
        if (length < l4_offset + 1) {
            return;
        }
        udp_layer = UDPLayer(data + l4_offset);
        has_udp = true;
        payload = (l4_offset < length) ? data + l4_offset : nullptr;
        payload_len = (l4_offset < length) ? (length - l4_offset) : 0;
        return;
    }
    else {
        // Unsupported L4 Protocol
        l4_type = L4Type::UNKNOWN;
    }
   
}   

// Print Packet View Details
void PacketView::print() const {
    std::cout << "=========== PACKET VIEW =============\n";

    if(has_eth) {
        eth_layer.print();
    }
    else { 
        std::cout << "Ethernet: <invalid>" << std::endl; 
        return; 
    }

    if(has_ip) {
        ip_layer.print();
    } 
    else { 
        std::cout << "IPv4: <invalid>" << std::endl;
        return; 
    }

    if(has_tcp) {
        tcp_layer.print();
    }
    else if(has_udp) {
        udp_layer.print();
    }
    else {
        std::cout << "Transport: <unsupported>" << std::endl;
    } 

    std::cout << "Payload Length: " << payload_len << " bytes" << std::endl;
    std::cout << "=====================================" << std::endl;
}

