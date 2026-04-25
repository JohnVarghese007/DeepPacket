#include "dp/validation/validation.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstddef>
#include <cstdint>
#include <string>
#include <cstring>
#include <arpa/inet.h>


namespace dp::validation {

using dp::parser::PacketView;
using dp::parser::layers::ARPLayer;
using dp::parser::layers::IPv4Layer;
using dp::parser::layers::IPv6Layer;
using dp::parser::layers::ICMPv4Layer;
using dp::parser::layers::ICMPv6Layer;
using dp::parser::layers::TCPLayer;
using dp::parser::layers::UDPLayer;
using dp::parser::EthernetHeader;
using dp::parser::ARPHeader;
using dp::parser::IPv4Header;
using dp::parser::IPv6Header;
using dp::parser::ICMPv4Header;
using dp::parser::ICMPv6Header;
using dp::parser::TCPHeader;
using dp::parser::UDPHeader;
using dp::parser::IpProto;

#define ETHERNET_HEADER_SIZE 14
#define ARP_HEADER_SIZE 8
#define ARP_HTYPE_ETHERNET 1
#define ARP_HLEN_ETHERNET 6
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2
#define IPV4_MIN_HEADER_SIZE 20
#define IPV4_MAX_HEADER_SIZE 60
#define IPV6_HEADER_SIZE 40
#define TCP_MIN_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPv4_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define IPv6_ETHERTYPE 0x86DD


// Utility/Helper functions

// Computes checksum using the internet checksum algorithm
uint16_t compute_checksum(const uint8_t* buffer, size_t len) {
    uint32_t sum = 0;

    while(len > 1) {
        uint16_t high = buffer[0] << 8;
        uint16_t low = buffer[1];
        uint16_t word = high | low;

        sum += word;
        buffer += 2;
        len -= 2;

        if(sum & 0x10000) {
            sum = (sum & 0xFFFF) + 1;
        }
    }

    // handle odd number of bytes
    if(len == 1){
        sum += buffer[0] << 8; 
        if(sum & 0x10000){
            sum = (sum & 0xFFFF) + 1;
        }
    }
    // return 16 bit ones complement as the computed checksum
    return  ~sum & 0xFFFF;
}




/*
    Packet Validator Class Implementation
    -  The PacketValidator class essentially handles the entire validation pipeline for DeepPacket
    -  Takes a PacketView object parsed by the parser module and validates its fields
    -  Deals with a set of validation errors defined in "packet-error.hpp"
    -  Contains public methods to print errors/raw bytes
*/

void  PacketValidator::validate_packet() {
  
    ValidationError err;
    errors.clear();

    // Layer 2: Ethernet Validation
    if(!validate_ethernet(view, err)) {
        errors.push_back(err);
        return;
    }

    uint16_t ethertype = ntohs(view.eth_layer.eth->ether_type);

    if(ethertype == ARP_ETHERTYPE) {    
        // Layer 2.5: ARP Validation
        if(!validate_arp(view, err)) {
            errors.push_back(err);
            return;
        }
        errors.push_back(ValidationError::NONE);
        return;
    }

    // Layer 3:  IPv4/IPv6 Validation
    if(ethertype == IPv4_ETHERTYPE) {
         if(!validate_ipv4(view, err)) {
            errors.push_back(err);
            return;
        }
    }
    else if (ethertype == IPv6_ETHERTYPE) {
        if(!validate_ipv6(view, err)) {
            errors.push_back(err);
            return;
        }
    }
    else {
        // validate ethernet alraedy should return INVALID_ETHERTYPE error, but just in case
        errors.push_back(ValidationError::INVALID_ETHERTYPE);
        return;
    }

    // IP Protocol Validation (TCP, UDP, ICMPv4, ICMPv6)
    switch (view.ip_proto) {
        case IpProto::TCP:
            if(!validate_tcp(view, err))
                errors.push_back(err);
            break;

        case IpProto::UDP:
            if(!validate_udp(view, err))
                errors.push_back(err);
            break;

        case IpProto::ICMPv4:
            if(!validate_icmpv4(view, err))
                errors.push_back(err);
            break; 

        case IpProto::ICMPv6:
            if(!validate_icmpv6(view, err))
                errors.push_back(err);
            break;

        default:
            errors.push_back(ValidationError::UNSUPPORTED_IP_PROTOCOL);
            break;
    }

    // If there are no errors add a NONE flag to show that validation was completed with no errors
    // Lack of a NONE flag with no other errors means validation was never done
    if(errors.empty())
        errors.push_back(ValidationError::NONE);

    return;
}



void PacketValidator::print_errors(std::ostream& os) const {
    for(ValidationError err: errors) {
        os << dp::validation::to_string(err) << std::endl;
    }

    // if there are no errors, not even NONE, that means validation never happened
    if(errors.empty()){
        os << "Error in Validation module" <<  std::endl;
        os << "Looks like validation never happened" << std::endl;
    }
}



void PacketValidator::print_raw_packet_bytes(std::ostream& os) const {
    const uint8_t* data = view.data;
    size_t len = view.size();

    os << std::hex << std::setfill('0');

    for(size_t i = 0; i < len; i++) {
        os << std::setw(2) << static_cast<int>(data[i]) << " ";

        // group into rows of 16 bytes
        if((i + 1) % 16 == 0) {
            os << std::endl;
        }
    }

    os << std::dec << std::endl;
}


std::string PacketValidator::to_string() const {
    std::ostringstream oss;
    if (errors.empty()) {
        oss << "Validation: OK\n";
        return oss.str();
    }

    oss << "Validation Errors:\n";
    for (auto err : errors) {
        oss << "  - " << dp::validation::to_string(err) << "\n";
    }

    return oss.str();
}


bool PacketValidator::validate_ethernet(const PacketView& view, ValidationError& error) {
    if (view.size() < ETHERNET_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_ETHERNET;
        return false;
    }

    uint16_t ethertype = ntohs(view.eth_layer.eth->ether_type);
    if (ethertype != IPv4_ETHERTYPE && ethertype != IPv6_ETHERTYPE && ethertype != ARP_ETHERTYPE) {
        error = ValidationError::INVALID_ETHERTYPE;
        return false;
    }

    return true;
}



bool PacketValidator::validate_arp(const PacketView& view, ValidationError& error) {
    const ARPLayer& arp_layer  = view.arp_layer;

    if(view.size() < ETHERNET_HEADER_SIZE + ARP_HEADER_SIZE) {
        error = ValidationError::ARP_TRUNCATED_HEADER;
        return false;
    }

    uint16_t htype  = ntohs(arp_layer.arp->hardware_type);
    if(htype != ARP_HTYPE_ETHERNET) {
        error = ValidationError::ARP_INVALID_HTYPE;
        return false;
    }

    uint16_t ptype  = ntohs(arp_layer.arp->protocol_type);
    if(ptype != IPv4_ETHERTYPE) {
        error = ValidationError::ARP_INVALID_PTYPE;
        return false;
    }

    uint8_t hlen = arp_layer.arp->hardware_len;
    if(hlen != ARP_HLEN_ETHERNET) {
        error = ValidationError::ARP_INVALID_HLEN;
        return false;
    }

    uint8_t plen = arp_layer.arp->protocol_len;
    if(plen != 4) {
        error = ValidationError::ARP_INVALID_PLEN;
        return false;
    }

    uint16_t opcode = ntohs(arp_layer.arp->opcode);
    if(opcode != ARP_OPCODE_REQUEST && opcode != ARP_OPCODE_REPLY){
        error = ValidationError::ARP_INVALID_OPCODE;
        return false;
    }

    size_t needed = 8 + (hlen * 2) + (plen * 2);
    if(view.size() < ETHERNET_HEADER_SIZE + needed) {
        error = ValidationError::ARP_TRUNCATED_ADDRESSES;
        return false;
    }

    if (opcode == ARP_OPCODE_REPLY) {
        const uint8_t* target_mac = arp_layer.arp->target_mac;
        bool broadcast = true;
        for (int i = 0; i < 6; i++)
            if (target_mac[i] != 0xFF)
                broadcast = false;

        if (broadcast) {
            error = ValidationError::ARP_REPLY_TO_BROADCAST;
            return false;
        }
    }

    return true;
}




bool PacketValidator::validate_ipv4(const PacketView& view, ValidationError& error) {
    const IPv4Layer& ip_layer = view.ipv4_layer;

    // Must have IPv4 header
    if (!view.has_ipv4 || !ip_layer.iph) {
        error = ValidationError::MISSING_IPV4_HEADER;
        return false;
    }

    // Minimum IPv4 header size
    if (view.size() < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_IPV4;
        return false;
    }

    // Version must be 4
    uint8_t version = ip_layer.iph->version_ihl >> 4;
    if (version != 4) {
        error = ValidationError::INVALID_IPV4_VERSION;
        return false;
    }

    // IHL must be >= 5 (20 bytes)
    uint8_t ihl = ip_layer.iph->version_ihl & 0x0F;
    if (ihl < 5) {
        error = ValidationError::INVALID_IPV4_IHL;
        return false;
    }

    size_t header_len = ihl * 4;

    // Header length must fit in packet
    if (view.size() < ETHERNET_HEADER_SIZE + header_len) {
        error = ValidationError::INVALID_IPV4_IHL_LENGTH;
        return false;
    }

    // Options truncated?
    if (header_len > IPV4_MAX_HEADER_SIZE) {
        error = ValidationError::IPV4_OPTIONS_TRUNCATED;
        return false;
    }

    // Total length must be >= header length
    uint16_t total_len = ntohs(ip_layer.iph->total_length);
    if (total_len < header_len) {
        error = ValidationError::INVALID_IPV4_TOTAL_LENGTH;
        return false;
    }

    // Total length must not exceed packet size
    if (total_len > view.size() - ETHERNET_HEADER_SIZE) {
        error = ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET;
        return false;
    }

    // Header checksum validation
    const uint8_t* ip_header = reinterpret_cast<const uint8_t*>(ip_layer.iph);
    uint8_t temp[IPV4_MAX_HEADER_SIZE];
    memcpy(temp, ip_header, header_len);

    // Zero checksum field before computing
    temp[10] = 0;
    temp[11] = 0;

    uint16_t computed = compute_checksum(temp, header_len);
    uint16_t received = ntohs(ip_layer.iph->header_checksum);

    if (computed != received) {
        error = ValidationError::IPV4_INVALID_CHECKSUM;
        return false;
    }

    return true;
}




bool PacketValidator::validate_ipv6(const PacketView& view, ValidationError& error) {
    const IPv6Layer& ip_layer = view.ipv6_layer;
    const IPv6Header* iph = ip_layer.iph;

    if(!view.has_ipv6 || !ip_layer.iph) {
        error = ValidationError::MISSING_IPV6_HEADER;
        return false;
    }

    // Packet must be large enough for Ethernet + IPv6 header(40 bytes)
    if(view.size() < ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_IPV6;
        return false;
    }

    // Version must be 6
    uint32_t vtcfl_field = ntohl(iph->version_tc_fl);
    uint8_t version = (vtcfl_field >> 28) & 0x0F;
    if (version != 6) {
        error = ValidationError::INVALID_IPV6_VERSION;
        return false;
    }

    // Payload length must not exceed packet size
    uint16_t payload_len = ntohs(iph->payload_length);
    size_t total_l3_len = IPV6_HEADER_SIZE + payload_len;
    size_t available_l3_len = view.size() - ETHERNET_HEADER_SIZE;

    if (payload_len == 0 && available_l3_len < IPV6_HEADER_SIZE) {
        error = ValidationError::INVALID_IPV6_PAYLOAD_LENGTH;
        return false;
    }

    if(total_l3_len > available_l3_len) {
        error = ValidationError::IPV6_PAYLOAD_EXCEEDS_PACKET;
        return false;
    }

    // Hop limit must be > 0
    if (iph->hop_limit == 0) {
        error = ValidationError::IPV6_HOP_LIMIT_ZERO;
        return false;
    }

    // Handling next header/extension header
    // We will only be detecting the presence of extension headers but not parsing/validating them 
    // ( DeepPacket does not currently support parsing/validation for IPv6 extension headers)
    uint8_t nh = iph->next_header;

    // Known extension headers we don't parse in v2
    if (nh == 0   ||  // Hop-by-Hop Options
        nh == 43  ||  // Routing
        nh == 44  ||  // Fragment
        nh == 50  ||  // ESP
        nh == 51  ||  // AH
        nh == 60)     // Destination Options
    {
        error = ValidationError::IPV6_EXTENSION_HEADER_UNSUPPORTED;
        return false;
    }

    // At this point we only structurally validate IPv6.
    // Unsupported next-header values (non-extension) are flagged here.
    switch (nh) {
        case 6:   // TCP
        case 17:  // UDP
        case 58:  // ICMPv6
            // Supported L4 protocols; deeper validation happens later
            break;
        default:
            error = ValidationError::IPV6_UNSUPPORTED_NEXT_HEADER;
            return false;
    }
    return true;
}



bool PacketValidator::validate_tcp(const PacketView& view, ValidationError& error) {
    const TCPHeader* tcp = view.tcp_layer.tcph;

    if (!view.has_tcp || !tcp) {
        error = ValidationError::MISSING_TCP_HEADER;
        return false;
    }

    size_t ip_header_len = 0;
    if (view.has_ipv4) {
        ip_header_len = view.ipv4_layer.header_size();
    }
    else if (view.has_ipv6) {
        ip_header_len = view.ipv6_layer.header_size();
    }
    else {
        ip_header_len = 0; // should never happen, but safe fallback
    }
    size_t tcp_offset = ETHERNET_HEADER_SIZE + ip_header_len;

    if (view.size() < tcp_offset + TCP_MIN_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_TCP;
        return false;
    }

    uint8_t data_offset = (tcp->data_offset >> 4);
    if (data_offset < 5) {
        error = ValidationError::INVALID_TCP_DATA_OFFSET;
        return false;
    }

    size_t tcp_header_len = data_offset * 4;
    if (view.size() < tcp_offset + tcp_header_len) {
        error = ValidationError::TCP_HEADER_EXCEEDS_PACKET;
        return false;
    }

    // Skip TCP checksum validation for live capture (checksum offloading)
    if (view.is_live_capture) {
        return true;
    }

    // Calculate TCP segment length for checksum depending on whether it's IPv4 or IPv6
    size_t tcp_len = 0;
    if (view.has_ipv4) {
        tcp_len = ntohs(view.ipv4_layer.iph->total_length) - ip_header_len;
    } else {
        tcp_len = ntohs(view.ipv6_layer.iph->payload_length); // entire IPv6 payload is TCP
    }

    // Build pseudo-header
    uint8_t pseudo[40];
    size_t pseudo_len = 0;

    if (view.has_ipv4) {
        const IPv4Header* iph = view.ipv4_layer.iph;

        memcpy(pseudo, iph->src_addr, 4);
        memcpy(pseudo + 4, iph->dest_addr, 4);
        pseudo[8]  = 0;
        pseudo[9]  = iph->protocol;
        pseudo[10] = (tcp_len >> 8) & 0xFF;
        pseudo[11] = tcp_len & 0xFF;
        pseudo_len = 12;

    } else {            
        const IPv6Header* iph = view.ipv6_layer.iph;
        memcpy(pseudo, iph->src_addr, 16);
        memcpy(pseudo + 16, iph->dest_addr, 16);
        pseudo[32] = (tcp_len >> 24) & 0xFF;
        pseudo[33] = (tcp_len >> 16) & 0xFF;
        pseudo[34] = (tcp_len >> 8) & 0xFF;
        pseudo[35] = tcp_len & 0xFF;
        pseudo[36] = 0;
        pseudo[37] = 0;
        pseudo[38] = 0;
        pseudo[39] = 6; // TCP
        pseudo_len = 40;
    }

    uint8_t temp[65535];
    memcpy(temp, view.data + tcp_offset, tcp_len);
    temp[16] = 0;
    temp[17] = 0;
    uint32_t sum = compute_checksum(pseudo, pseudo_len) + compute_checksum(temp, tcp_len);

    // Fold carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t computed = ~sum & 0xFFFF;
    uint16_t received = ntohs(tcp->checksum);
    // line added for debugging
    // std::cout << "Computed" << std::hex << computed << "\tRecieved" << received << std::dec << std::endl;
    if (computed != received) {
        error = ValidationError::TCP_INVALID_CHECKSUM;
        return false;
    }

    return true;
}



bool PacketValidator::validate_udp(const PacketView& view, ValidationError& error) {
    const UDPHeader* udph = view.udp_layer.udph;

    if (!view.has_udp || !udph) {
        error = ValidationError::MISSING_UDP_HEADER;
        return false;
    }

    // Compute UDP offset based on Ethernet + IP header sizes
    size_t ip_header_len = 0;
    if (view.has_ipv4) {
        ip_header_len = view.ipv4_layer.header_size();
    }
    else if (view.has_ipv6) {
        ip_header_len = view.ipv6_layer.header_size();
    }
    else {
        ip_header_len = 0;
    }
    size_t udp_offset = ETHERNET_HEADER_SIZE + ip_header_len;

    if (view.size() < udp_offset + UDP_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_UDP;
        return false;
    }

    uint16_t udp_len = ntohs(udph->length);
    if (udp_len < UDP_HEADER_SIZE) {
        error = ValidationError::INVALID_UDP_LENGTH;
        return false;
    }

    if (udp_len > view.size() - udp_offset) {
        error = ValidationError::UDP_LENGTH_EXCEEDS_PACKET;
        return false;
    }

    // Skip UDP checksum validation for live capture (checksum offloading)
    if (view.is_live_capture) {
        return true;
    }

    // UDP checksum of 0 means "no checksum" in IPv4
    if (view.has_ipv4 && udph->checksum == 0) {
        return true;
    }

    if (view.has_ipv6 && udph->checksum == 0) {
        error = ValidationError::UDP_INVALID_CHECKSUM;
        return false;
    }

    size_t udp_length = udp_len; 

    // Build pseudo-header
    uint8_t pseudo[40];
    size_t pseudo_len = 0;

    if (view.has_ipv4) {
        const IPv4Header* iph = view.ipv4_layer.iph;
        memcpy(pseudo, iph->src_addr, 4);
        memcpy(pseudo + 4, iph->dest_addr, 4);
        pseudo[8]  = 0;
        pseudo[9]  = iph->protocol;
        pseudo[10] = (udp_len >> 8) & 0xFF;
        pseudo[11] = udp_len & 0xFF;
        pseudo_len = 12;
    } else {
        const IPv6Header* iph = view.ipv6_layer.iph;
        memcpy(pseudo, iph->src_addr, 16);
        memcpy(pseudo + 16, iph->dest_addr, 16);
        pseudo[32] = (udp_len >> 24) & 0xFF;
        pseudo[33] = (udp_len >> 16) & 0xFF;
        pseudo[34] = (udp_len >> 8) & 0xFF;
        pseudo[35] = udp_len & 0xFF;
        pseudo[36] = 0;
        pseudo[37] = 0;
        pseudo[38] = 0;
        pseudo[39] = 17; // UDP
        pseudo_len = 40;
    }

    // Copy UDP header + payload
    uint8_t temp[65535];
    memcpy(temp, view.data + udp_offset, udp_length);

    // Zero checksum field
    temp[6] = 0;
    temp[7] = 0;

    uint32_t sum = compute_checksum(pseudo, pseudo_len) + compute_checksum(temp, udp_length);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t computed = ~sum & 0xFFFF;
    uint16_t received = ntohs(udph->checksum);

    // line added for debugging
    // std::cout << "Computed" << std::hex << computed << "\tRecieved" << received << std::dec << std::endl;
    if (computed != received) {
        error = ValidationError::UDP_INVALID_CHECKSUM;
        return false;
    }

    return true;
}



bool PacketValidator::validate_icmpv4(const PacketView& view, ValidationError& error) {
    const ICMPv4Layer& icmp_layer = view.icmpv4_layer;
    const ICMPv4Header* icmp = icmp_layer.icmph;

    // Must have ICMPv4 header
    if (!view.has_icmpv4 || !icmp) {
        error = ValidationError::MISSING_ICMPV4_HEADER;
        return false;
    }

    // Compute ICMP offset and header size
    size_t ip_header_len = view.ipv4_layer.header_size();
    size_t icmp_offset = ETHERNET_HEADER_SIZE + ip_header_len;
    size_t icmp_header_len = icmp_layer.header_size();

    if (view.size() < icmp_offset + icmp_header_len) {
        error = ValidationError::TOO_SMALL_FOR_ICMPV4;
        return false;
    }

    // Validate ICMPv4 type
    switch (icmp->type) {
        case 0:   // Echo reply
        case 8:   // Echo request
            if (icmp->code != 0) {
                error = ValidationError::ICMPV4_INVALID_CODE;
                return false;
            }
            break;

        case 3:   // Destination Unreachable
            if (icmp->code > 15) {
                error = ValidationError::ICMPV4_INVALID_CODE;
                return false;
            }
            break;

        case 5:   // Redirect
            if (icmp->code > 3) {
                error = ValidationError::ICMPV4_INVALID_CODE;
                return false;
            }
            break;

        case 12:  // Parameter Problem
            if (icmp->code > 2) {
                error = ValidationError::ICMPV4_INVALID_CODE;
                return false;
            }
            break;

        default:
            error = ValidationError::ICMPV4_INVALID_TYPE;
            return false;
    }

    // Compute total ICMP length from IPv4 total_length
    uint16_t total_len = ntohs(view.ipv4_layer.iph->total_length);
    size_t icmp_len = total_len - ip_header_len;

    // Error-type ICMP messages must contain embedded IPv4 header + 8 bytes
    if (icmp->type == 3 || icmp->type == 5 || icmp->type == 12) {
        size_t payload_len = icmp_len - icmp_header_len;

        if (payload_len < 28) { // 20 bytes IPv4 header + 8 bytes of original L4
            error = ValidationError::ICMPV4_TRUNCATED_PAYLOAD;
            return false;
        }

        // Validate embedded IPv4 header (structural only)
        const uint8_t* inner_ptr = view.data + icmp_offset + icmp_header_len;
        const IPv4Header* inner = reinterpret_cast<const IPv4Header*>(inner_ptr);

        uint8_t inner_version = inner->version_ihl >> 4;
        if (inner_version != 4) {
            error = ValidationError::ICMPV4_EMBEDDED_IPV4_INVALID;
            return false;
        }

        uint8_t inner_ihl = inner->version_ihl & 0x0F;
        if (inner_ihl < 5) {
            error = ValidationError::ICMPV4_EMBEDDED_IPV4_INVALID;
            return false;
        }

        size_t inner_header_len = inner_ihl * 4;
        uint16_t inner_total_len = ntohs(inner->total_length);

        if (inner_total_len < inner_header_len) {
            error = ValidationError::ICMPV4_EMBEDDED_IPV4_INVALID;
            return false;
        }
    }

    // Checksum validation (ICMPv4 uses NO pseudo-header)
    uint16_t received = ntohs(icmp->checksum);

    uint8_t temp[65535];
    memcpy(temp, view.data + icmp_offset, icmp_len);

    // Zero checksum field before computing
    temp[2] = 0;
    temp[3] = 0;

    uint16_t computed = compute_checksum(temp, icmp_len);

    if (computed != received) {
        error = ValidationError::ICMPV4_INVALID_CHECKSUM;
        return false;
    }

    return true;
}



bool PacketValidator::validate_icmpv6(const PacketView& view, ValidationError& error) {
    const ICMPv6Layer& icmp_layer = view.icmpv6_layer;
    const ICMPv6Header* icmp = icmp_layer.icmph;

    // Must have ICMPv6 header
    if (!view.has_icmpv6 || !icmp) {
        error = ValidationError::ICMPV6_MISSING_HEADER;
        return false;
    }

    // Compute ICMPv6 offset
    size_t ip_header_len = view.ipv6_layer.header_size(); // always 40
    size_t icmp_offset = ETHERNET_HEADER_SIZE + ip_header_len;
    size_t icmp_header_len = icmp_layer.header_size();

    if (view.size() < icmp_offset + icmp_header_len) {
        error = ValidationError::ICMPV6_TOO_SMALL;
        return false;
    }

    // Validate ICMPv6 type/code (RFC 4443)
    switch (icmp->type) {
        // Error messages (0–127)
        case 1:  // Destination Unreachable
            if (icmp->code > 6) {
                error = ValidationError::ICMPV6_INVALID_CODE;
                return false;
            }
            break;

        case 2:  // Packet Too Big
            if (icmp->code != 0) {
                error = ValidationError::ICMPV6_INVALID_CODE;
                return false;
            }
            break;

        case 3:  // Time Exceeded
            if (icmp->code > 1) {
                error = ValidationError::ICMPV6_INVALID_CODE;
                return false;
            }
            break;

        case 4:  // Parameter Problem
            if (icmp->code > 2) {
                error = ValidationError::ICMPV6_INVALID_CODE;
                return false;
            }
            break;

        // Informational messages (128–255)
        case 128: // Echo Request
        case 129: // Echo Reply
            if (icmp->code != 0) {
                error = ValidationError::ICMPV6_INVALID_CODE;
                return false;
            }
            break;

        default:
            // Unknown or unsupported ICMPv6 type
            error = ValidationError::ICMPV6_INVALID_TYPE;
            return false;
    }

    // RFC 4443: ICMPv6 error messages MUST NOT be sent in response to ICMPv6 error messages
    if (icmp->type <= 4) { // this is an ICMPv6 error message
        const uint8_t* inner_ptr = view.data + icmp_offset + icmp_header_len;
        const IPv6Header* inner_ip6 = reinterpret_cast<const IPv6Header*>(inner_ptr);

        // Check if embedded packet is also ICMPv6
        uint8_t inner_next_header = inner_ip6->next_header;

        if (inner_next_header == 58) { // ICMPv6
            const ICMPv6Header* inner_icmp =
            reinterpret_cast<const ICMPv6Header*>(inner_ptr + sizeof(IPv6Header));

            // If inner ICMPv6 is also an error (type 0–4), this is invalid
            if (inner_icmp->type <= 4) {
                error = ValidationError::ICMPV6_ERROR_MESSAGE_INVALID;
                return false;
            
            }
        }
    }


    // Compute ICMPv6 length from IPv6 payload_length
    uint16_t payload_len = ntohs(view.ipv6_layer.iph->payload_length);
    size_t icmp_len = payload_len; // ICMPv6 occupies entire payload

    if (icmp_len < icmp_header_len) {
        error = ValidationError::ICMPV6_TOO_SMALL;
        return false;
    }

    // Error messages must include embedded IPv6 header + 8 bytes
    if (icmp->type <= 4) { // error messages
        size_t payload_after_header = icmp_len - icmp_header_len;

        if (payload_after_header < 48) { // 40 bytes IPv6 header + 8 bytes of original L4
            error = ValidationError::ICMPV6_TRUNCATED_PAYLOAD;
            return false;
        }

        // Validate embedded IPv6 header (structural only)
        const uint8_t* inner_ptr = view.data + icmp_offset + icmp_header_len;
        const IPv6Header* inner = reinterpret_cast<const IPv6Header*>(inner_ptr);

        uint32_t inner_vtcfl = ntohl(inner->version_tc_fl);
        uint8_t inner_version = (inner_vtcfl >> 28) & 0x0F;

        if (inner_version != 6) {
            error = ValidationError::ICMPV6_EMBEDDED_IPV6_INVALID;
            return false;
        }
    }

    // Checksum must not be zero in IPv6
    uint16_t received = ntohs(icmp->checksum);
    if (received == 0) {
        error = ValidationError::ICMPV6_INVALID_CHECKSUM;
        return false;
    }

    // Build IPv6 pseudo-header for checksum
    const IPv6Header* ip6h = view.ipv6_layer.iph;

    uint8_t pseudo[40]; // 16 src + 16 dst + 4 length + 3 zero + 1 next_header
    memcpy(pseudo, ip6h->src_addr, 16);
    memcpy(pseudo + 16, ip6h->dest_addr, 16);

    // Payload length (ICMPv6 length)
    pseudo[32] = (icmp_len >> 24) & 0xFF;
    pseudo[33] = (icmp_len >> 16) & 0xFF;
    pseudo[34] = (icmp_len >> 8) & 0xFF;
    pseudo[35] = icmp_len & 0xFF;

    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = 58; // next header = ICMPv6

    // Copy ICMPv6 message
    uint8_t temp[65535];
    memcpy(temp, view.data + icmp_offset, icmp_len);

    // Zero checksum field
    temp[2] = 0;
    temp[3] = 0;

    // Compute checksum
    uint32_t sum = compute_checksum(pseudo, sizeof(pseudo));
    sum += compute_checksum(temp, icmp_len);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t computed = ~sum & 0xFFFF;

    if (computed != received) {
        error = ValidationError::ICMPV6_INVALID_CHECKSUM;
        return false;
    }

    return true;
}



} // namespace dp::validation