#include "packet_view.hpp"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

// PacketView Constructor
PacketView::PacketView(const uint8_t* packet) {
    eth_layer = new EthernetLayer(packet);
    ip_layer = new IPv4Layer(packet + eth_layer->header_size());
    size_t ip_header_size = ip_layer->header_size();
    const uint8_t* l4_start = packet + eth_layer->header_size() + ip_header_size;

    // Determine Layer 4 Protocol based on Ipv4 protocol field (TCP=6, UDP=17)
    if(ip_layer->iph->protocol == 6) {
        tcp_layer = new TCPLayer(l4_start);
        udp_layer = nullptr;
        l4_type = L4Type::TCP;
        size_t tcp_header_size = tcp_layer->header_size();
        payload = l4_start + tcp_header_size;
        payload_len = ntohs(ip_layer->iph->total_length) - ip_header_size - tcp_header_size;
    }
    else if(ip_layer->iph->protocol == 17) {
        udp_layer = new UDPLayer(l4_start);
        tcp_layer = nullptr;
        l4_type = L4Type::UDP;
        payload = l4_start + udp_layer->header_size();
        payload_len = ntohs(udp_layer->udph->length) - udp_layer->header_size();
    }
    else {
        tcp_layer = nullptr;
        udp_layer = nullptr;
        l4_type = L4Type::UNKNOWN;
        payload = nullptr;
        payload_len = 0;
    }
}

// PacketView Destructor
PacketView::~PacketView() {
    delete eth_layer;
    delete ip_layer;
    delete tcp_layer;
    delete udp_layer;
}

// Print Packet Details
void PacketView::print() const {
    std::cout << "=========== PACKET VIEW ============="  << std::endl;
        eth_layer->print();
        ip_layer->print();
        if(l4_type == L4Type::TCP) {
            tcp_layer->print();
        }
        else if(l4_type == L4Type::UDP) {
            udp_layer->print();
        }
        else {
            std::cout << "=== Unsupported L4 Protocol ===" << std::endl;

        }
        std::cout << "Payload Length: " << payload_len << " bytes" << std::endl;
        std::cout << "=====================================" << std::endl;
}


