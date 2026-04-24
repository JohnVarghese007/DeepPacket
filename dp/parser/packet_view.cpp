#include "packet_view.hpp"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>


namespace dp::parser {

#define ICMP_PROTOCOL_VALUE 1
#define TCP_PROTOCOL_VALUE 6
#define UDP_PROTOCOL_VALUE 17
#define IPv4_ETHERTYPE 0x0800
#define IPv6_ETHERTYPE 0x08DD
#define ARP_ETHERTYPE 0x0806
#define MINIMUM_TCP_HEADER_SIZE 20
#define MINIMUM_UDP_HEADER_SIZE 8

/*
    PacketView Class Implementation
    - This class provides a structural view of a raw network packet
    - parses raw byte buffer into supported protocol layers (Ethernet, ARP, IPv4, TCP, UDP)
    - Does not handle validation -> that is to be done separately by the validation module
*/

// PacketView Constructor
PacketView::PacketView(const uint8_t* packet, size_t length) :
    data(packet), length(length), 
    has_eth(false), has_arp(false), has_ip(false), has_tcp(false), has_udp(false), has_icmp(false),
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
    eth_layer = layers::EthernetLayer(data);
    has_eth = true;

    // EtherType check(ARP, IPv4)
    uint16_t ethertype = ntohs(eth_layer.eth->ether_type);

    if (ethertype == ARP_ETHERTYPE) {
        // ARP Layer
        arp_layer = layers::ARPLayer(data + eth_layer.header_size());
        has_arp = true;
    }
    else if (ethertype == IPv4_ETHERTYPE) {
        // IPv4 Layer
        size_t ip_offset = sizeof(EthernetHeader);
        if (length < ip_offset + 1) {
            return;
        }
        ip_layer = layers::IPv4Layer(data + ip_offset);
        has_ip = true;

        // Looking at ihl bits to determine IPv4 header size
        size_t ihl = (ip_layer.iph->version_ihl & 0x0F) * 4;

        // ihl bounds checks
        if (ihl < 20)
            return;

        if (ip_offset + ihl > length)
            return;

        // Adding ihl to ip_offset to point to L4 header
        size_t l4_offset = ip_offset + ihl;    

        // Determining Layer 4 Protocol
        if(ip_layer.iph->protocol == TCP_PROTOCOL_VALUE) {
            l4_type = L4Type::TCP;
            if (length < l4_offset + 1) {
                return;
            }
            tcp_layer = layers::TCPLayer(data + l4_offset);
            has_tcp = true;

            size_t tcp_header_len = ((tcp_layer.tcph->data_offset >> 4) & 0x0F) * 4;

            if (tcp_header_len < MINIMUM_TCP_HEADER_SIZE || l4_offset + tcp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }

            payload = data + l4_offset + tcp_header_len;
            payload_len = length - (l4_offset + tcp_header_len);
       
        }
        else if(ip_layer.iph->protocol == UDP_PROTOCOL_VALUE) {
            l4_type = L4Type::UDP;
            if (length < l4_offset + 1) {
                return;
            }
            // UDP branch
            udp_layer = layers::UDPLayer(data + l4_offset);
            has_udp = true;

            size_t udp_header_len = MINIMUM_UDP_HEADER_SIZE;

            if (l4_offset + udp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }

            payload = data + l4_offset + udp_header_len;
            payload_len = length - (l4_offset + udp_header_len);
        }
        else if(ip_layer.iph->protocol == ICMP_PROTOCOL_VALUE){
            l4_type = L4Type::ICMP;

            if (length < l4_offset + sizeof(ICMPFixedHeader)) {
                return;
            }

            // Parse ICMP
            icmp_layer = layers::ICMPLayer(data + l4_offset);
            has_icmp = true;

            size_t icmp_header_len = icmp_layer.header_size();

            if (l4_offset + icmp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }

            payload = data + l4_offset + icmp_header_len;
            payload_len = length - (l4_offset + icmp_header_len);
        }
        else {
            // Unsupported L4 Protocol
            l4_type = L4Type::UNKNOWN;
        }
    }    
   
}   



// Print Packet View Details
void PacketView::print(std::ostream& os) const {
    os << "=========== PACKET VIEW =============" << std::endl;

    if(has_eth) {
        eth_layer.print(os);
    }
    else { 
        os << "Ethernet: <invalid>" << std::endl; 
        return; 
    }

    // ARP Packets do not go down further
    if (has_arp) {
        arp_layer.print(os);
        os << "=====================================" << std::endl;
        return;
    }

    if(has_ip) {
        ip_layer.print(os);
    } 
    else { 
        os << "IPv4: <invalid>" << std::endl;
        return; 
    }

    if(has_tcp) {
        tcp_layer.print(os);
    }
    else if(has_udp) {
        udp_layer.print(os);
    }
    else if(has_icmp) {
        icmp_layer.print(os);
    }
    else {
        os << "Transport: <unsupported>" << std::endl;
    } 

    os << "Payload Length: " << payload_len << " bytes" << std::endl;
    os << "=====================================" << std::endl;
}


} // namespace dp::parser
