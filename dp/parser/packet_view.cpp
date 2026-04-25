#include "dp/parser/packet_view.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>


namespace dp::parser {

#define ICMPV4_PROTOCOL_VALUE 1
#define ICMPV6_PROTOCOL_VALUE 58
#define TCP_PROTOCOL_VALUE 6
#define UDP_PROTOCOL_VALUE 17
#define IPv4_ETHERTYPE 0x0800
#define IPv6_ETHERTYPE 0x86DD
#define ARP_ETHERTYPE 0x0806
#define MINIMUM_TCP_HEADER_SIZE 20
#define MINIMUM_UDP_HEADER_SIZE 8

/*
    PacketView Class Implementation
    - This class provides a structural view of a raw network packet
    - parses raw byte buffer into supported protocol layers (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMPv4, ICMPv6)
    - Does not handle validation -> that is to be done separately by the validation module
*/

// PacketView Constructor
PacketView::PacketView(const uint8_t* packet, size_t length) :
    data(packet), length(length), 
    has_eth(false), has_arp(false), has_ipv4(false), has_ipv6(false), has_tcp(false), has_udp(false), has_icmpv4(false), has_icmpv6(false),
    payload(nullptr), payload_len(0), ip_proto(IpProto::UNKNOWN)
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

    // EtherType check(ARP, IPv4, IPv6)
    uint16_t ethertype = ntohs(eth_layer.eth->ether_type);

    if (ethertype == ARP_ETHERTYPE) {
        // ARP Layer
        arp_layer = layers::ARPLayer(data + eth_layer.header_size());
        has_arp = true;
        return;
    }
    else if (ethertype == IPv6_ETHERTYPE) {
        // IPv6 Layer
        size_t ipv6_offset = sizeof(EthernetHeader);
        if(length < ipv6_offset + 1) { 
            return;
        }
        ipv6_layer = layers::IPv6Layer(data + ipv6_offset);
        has_ipv6 = true;

        // IPv6 has fixed header size of 40 bytes
        size_t l4_offset = ipv6_offset + sizeof(IPv6Header);
        uint8_t next_header = ipv6_layer.iph->next_header;

        // Detecting but not parsing extension headers ( DeepPacket does not currently support parsing IPv6 extension headers) 
        if (next_header == 0   ||  // Hop-by-Hop Options
            next_header == 43  ||  // Routing Header
            next_header == 44  ||  // Fragment Header
            next_header == 50  ||  // ESP
            next_header == 51  ||  // AH
            next_header == 60)     // Destination Options
        {
            ip_proto = IpProto::UNKNOWN;
            has_tcp = has_udp = has_icmpv6 = false;

            // TODO: validation: IPV6_EXTENSION_HEADER_UNSUPPORTED
            return;
        }
        
        // Determining Next Protocol (TCP, UDP, ICMPv6 or UNKNOWN)
        if(next_header == TCP_PROTOCOL_VALUE) {
            ip_proto = IpProto::TCP;

            if(length < l4_offset + 1) {
                return;
            }
            tcp_layer = layers::TCPLayer(data + l4_offset);
            has_tcp = true;

            size_t tcp_header_len = tcp_layer.header_size();
            if (tcp_header_len < MINIMUM_TCP_HEADER_SIZE || l4_offset + tcp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }

            payload = data + l4_offset + tcp_header_len;
            payload_len = length - (l4_offset + tcp_header_len);
        }
        else if(next_header == UDP_PROTOCOL_VALUE) {
            ip_proto = IpProto::UDP;

            if(length < l4_offset + 1) {
                return;
            }
            udp_layer = layers::UDPLayer(data + l4_offset);
            has_udp = true;

            size_t udp_header_len = udp_layer.header_size();
            if (l4_offset + udp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }
            payload = data + l4_offset + udp_header_len;
            payload_len = length - (l4_offset + udp_header_len);
        }
        else if(next_header == ICMPV6_PROTOCOL_VALUE){
            ip_proto = IpProto::ICMPv6;
            if(length < l4_offset + sizeof(ICMPv6Header)) {
                return;
            }
            icmpv6_layer = layers::ICMPv6Layer(data + l4_offset);
            has_icmpv6 = true;

            size_t icmp_header_len = icmpv6_layer.header_size();
            if (l4_offset + icmp_header_len > length) {
                payload = nullptr;
                payload_len = 0;
                return;
            }
            payload = data + l4_offset + icmp_header_len;
            payload_len = length - (l4_offset + icmp_header_len);
        }
        else {
            // Unsupported IP protocol
            ip_proto = IpProto::UNKNOWN;
        }
    }
    else if (ethertype == IPv4_ETHERTYPE) {
        // IPv4 Layer
        size_t ipv4_offset = sizeof(EthernetHeader);
        if (length < ipv4_offset + 1) {
            return;
        }
        ipv4_layer = layers::IPv4Layer(data + ipv4_offset);
        has_ipv4 = true;

        // Looking at ihl bits to determine IPv4 header size
        size_t ihl = (ipv4_layer.iph->version_ihl & 0x0F) * 4;

        // ihl bounds checks
        if (ihl < 20)
            return;

        if (ipv4_offset + ihl > length)
            return;

        // Adding ihl to ipv4_offset to point to L4 header
        size_t l4_offset = ipv4_offset + ihl;    

        // Determining Next Protocol (TCP, UDP, ICMPv4 or UNKNOWN)
        if(ipv4_layer.iph->protocol == TCP_PROTOCOL_VALUE) {
            ip_proto = IpProto::TCP;
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
        else if(ipv4_layer.iph->protocol == UDP_PROTOCOL_VALUE) {
            ip_proto = IpProto::UDP;
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
        else if(ipv4_layer.iph->protocol == ICMPV4_PROTOCOL_VALUE){
            ip_proto = IpProto::ICMPv4;

            if (length < l4_offset + sizeof(ICMPv4Header)) {
                return;
            }

            // Parse ICMP
            icmpv4_layer = layers::ICMPv4Layer(data + l4_offset);
            has_icmpv4 = true;

            size_t icmp_header_len = icmpv4_layer.header_size();

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
            ip_proto = IpProto::UNKNOWN;
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

    if(has_ipv4) {
        ipv4_layer.print(os);
    } 
    else if (has_ipv6) {
        ipv6_layer.print(os);
    }
    else { 
        os << "IP: <invalid>" << std::endl;
        return; 
    }

    if(has_tcp) {
        tcp_layer.print(os);
    }
    else if(has_udp) {
        udp_layer.print(os);
    }
    else if(has_icmpv4) {
        icmpv4_layer.print(os);
    }
    else if(has_icmpv6) {
        icmpv6_layer.print(os);
    }
    else {
        os << "Transport: <unsupported>" << std::endl;
    } 

    os << "Payload Length: " << payload_len << " bytes" << std::endl;
    os << "=====================================" << std::endl;
}

// String representation of packet view (for CLI output)
std::string PacketView::to_string() const {
    std::ostringstream oss;
    print(oss);
    return oss.str();
}


} // namespace dp::parser
