#include "dp/validation/validation.hpp"
#include <iostream>
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
using dp::parser::layers::TCPLayer;
using dp::parser::layers::UDPLayer;
using dp::parser::layers::ICMPLayer;
using dp::parser::EthernetHeader;
using dp::parser::ARPHeader;
using dp::parser::IPv4Header;
using dp::parser::TCPHeader;
using dp::parser::UDPHeader;
using dp::parser::ICMPFixedHeader;
using dp::parser::L4Type;

#define ETHERNET_HEADER_SIZE 14
#define ARP_HEADER_SIZE 8
#define ARP_HTYPE_ETHERNET 1
#define ARP_HLEN_ETHERNET 6
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2
#define IPV4_MIN_HEADER_SIZE 20
#define IPV4_MAX_HEADER_SIZE 60
#define TCP_MIN_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPv4_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define IPv6_ETHERTYPE 0x08DD


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

    // Layer 3: IPv4 Validation
    if(!validate_ipv4(view, err)) {
        errors.push_back(err);
        return;
    }

    // Layer 4 Protocols based on l4_type
    switch (view.l4_type) {
        case L4Type::TCP:
            if(!validate_tcp(view, err))
                errors.push_back(err);
            break;

        case L4Type::UDP:
            if(!validate_udp(view, err))
                errors.push_back(err);
            break;

        case L4Type::ICMP:
            if(!validate_icmp(view, err))
                errors.push_back(err);
            break; 

        default:
            errors.push_back(ValidationError::UNSUPPORTED_L4_PROTOCOL);
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
        os << to_string(err) << std::endl;
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



bool PacketValidator::validate_ethernet(const PacketView& view, ValidationError& error) {
    if (view.size() < ETHERNET_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_ETHERNET;
        return false;
    }

    uint16_t ethertype = ntohs(view.eth_layer.eth->ether_type);
    if (ethertype != IPv4_ETHERTYPE && ethertype != ARP_ETHERTYPE) {
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
    const IPv4Layer& ip_layer = view.ip_layer;

    if(!view.has_ip || !ip_layer.iph) {
        error = ValidationError::MISSING_IPV4_HEADER;
        return false;
    }

    if(view.size() < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_IPV4;
        return false;
    }

    uint8_t version = ip_layer.iph->version_ihl >> 4;
    if(version != 4) {
        error = ValidationError::INVALID_IPV4_VERSION;
        return false;
    }

    uint8_t ihl = ip_layer.iph->version_ihl & 0x0F;
    if(ihl < 5) {
        error = ValidationError::INVALID_IPV4_IHL;
        return false;
    }

    size_t header_len = ihl * 4;
    if(view.size() < ETHERNET_HEADER_SIZE + header_len) {
        error = ValidationError::INVALID_IPV4_IHL_LENGTH;
        return false;
    }

    uint16_t total_len = ntohs(ip_layer.iph->total_length);
    if(total_len < header_len){
        error = ValidationError::INVALID_IPV4_TOTAL_LENGTH;
        return false;
    }

    if(total_len > view.size() -  ETHERNET_HEADER_SIZE) {
        error = ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET;
        return false;
    }

    // Checksum validation 
    const uint8_t* ip_header = reinterpret_cast<const uint8_t*>(ip_layer.iph);
    size_t ip_header_len = header_len;

    uint8_t temp[IPV4_MAX_HEADER_SIZE]; 
    memcpy(temp, ip_header, ip_header_len);

    temp[10] = 0;
    temp[11] = 0;
    uint16_t computed = compute_checksum(temp, ip_header_len);
    uint16_t received = ntohs(ip_layer.iph->header_checksum);

    if (computed != received) {
        error = ValidationError::IPV4_INVALID_CHECKSUM;
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

    size_t tcp_offset = ETHERNET_HEADER_SIZE + view.ip_layer.header_size();
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

    // Checksum validation for TCP
    const IPv4Header* iph = view.ip_layer.iph;
    const TCPHeader* tcph = view.tcp_layer.tcph;
    size_t ip_header_len = view.ip_layer.header_size();
    tcp_offset = ETHERNET_HEADER_SIZE + ip_header_len;
    size_t tcp_len = ntohs(iph->total_length) - ip_header_len;

    // Build pseudo-header
    uint8_t pseudo[12];
    memcpy(pseudo, &iph->src_addr, 4);
    memcpy(pseudo + 4, &iph->dest_addr, 4);
    pseudo[8]  = 0;
    pseudo[9]  = iph->protocol;
    pseudo[10] = (tcp_len >> 8) & 0xFF;
    pseudo[11] = tcp_len & 0xFF;

    uint8_t temp[65535];
    memcpy(temp, view.data + tcp_offset, tcp_len);

    // Zero checksum field
    temp[16] = 0;
    temp[17] = 0;
    uint32_t sum = 0;
    sum = compute_checksum(pseudo, 12) + compute_checksum(temp, tcp_len);

    // Fold carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t computed = ~sum & 0xFFFF;
    uint16_t received = ntohs(tcph->checksum);
    // line added for debugging
    // std::cout << "Computed" << std::hex << computed << "\tRecieved" << received << std::dec << std::endl;
    if (computed != received) {
        error = ValidationError::TCP_INVALID_CHECKSUM;
        return false;
    }

    return true;
}



bool PacketValidator::validate_udp(const PacketView& view, ValidationError& error) {
    const UDPHeader* udp = view.udp_layer.udph;

    if (!view.has_udp || !udp) {
        error = ValidationError::MISSING_UDP_HEADER;
        return false;
    }

    size_t udp_offset = ETHERNET_HEADER_SIZE + view.ip_layer.header_size();
    if (view.size() < udp_offset + UDP_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_UDP;
        return false;
    }

    uint16_t udp_len = ntohs(udp->length);
    if (udp_len < UDP_HEADER_SIZE) {
        error = ValidationError::INVALID_UDP_LENGTH;
        return false;
    }

    if (udp_len > view.size() - udp_offset) {
        error = ValidationError::UDP_LENGTH_EXCEEDS_PACKET;
        return false;
    }

    // Checksum validation for UDP
    const IPv4Header* iph = view.ip_layer.iph;
    const UDPHeader* udph = view.udp_layer.udph;

    // UDP checksum of 0 means "no checksum" in IPv4
    if (udph->checksum == 0)
        return true;

    size_t ip_header_len = view.ip_layer.header_size();
    udp_offset = ETHERNET_HEADER_SIZE + ip_header_len;
    size_t udp_length = ntohs(udph->length);

    // Build pseudo-header
    uint8_t pseudo[12];
    memcpy(pseudo, &iph->src_addr, 4);
    memcpy(pseudo + 4, &iph->dest_addr, 4);
    pseudo[8]  = 0;
    pseudo[9]  = iph->protocol;
    pseudo[10] = (udp_length >> 8) & 0xFF;
    pseudo[11] = udp_length & 0xFF;

    // Copy UDP header + payload
    uint8_t temp[65535];
    memcpy(temp, view.data + udp_offset, udp_length);

    // Zero checksum field
    temp[6] = 0;
    temp[7] = 0;

    uint32_t sum = 0;
    sum = compute_checksum(pseudo, 12) + compute_checksum(temp, udp_length);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

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



bool PacketValidator::validate_icmp(const PacketView& view, ValidationError& error) {
    const ICMPFixedHeader* icmp = view.icmp_layer.icmph;

    if (!view.has_icmp || !icmp) {
        error = ValidationError::MISSING_ICMP_HEADER;
        return false;
    }

    size_t icmp_offset = ETHERNET_HEADER_SIZE + view.ip_layer.header_size();
    size_t icmp_header_len = view.icmp_layer.header_size();
    if (view.size() < icmp_offset + icmp_header_len) {
        error = ValidationError::TOO_SMALL_FOR_ICMP;
        return false;
    }

    // valid type
    if (icmp->type != 0 && icmp->type != 3 && icmp->type != 5 &&
        icmp->type != 8 && icmp->type != 12) {
        error = ValidationError::ICMP_INVALID_TYPE;
        return false;
    }

    // valid codes for respective types
    switch (icmp->type) {
        case 0:
        case 8:
            if (icmp->code != 0) {
                error = ValidationError::ICMP_INVALID_CODE;
                return false;
            }
            break;

        case 3:
            if (icmp->code > 15) {
                error = ValidationError::ICMP_INVALID_CODE;
                return false;
            }
            break;

        case 5:
            if (icmp->code > 3) {
                error = ValidationError::ICMP_INVALID_CODE;
                return false;
            }
            break;

        case 12:
            if (icmp->code > 2) {
                error = ValidationError::ICMP_INVALID_CODE;
                return false;
            }
            break;
    }

    size_t icmp_len = ntohs(view.ip_layer.iph->total_length) - view.ip_layer.header_size();

    if (icmp->type == 3 || icmp->type == 5 || icmp->type == 12) {
        // truncated payload
        size_t payload_len = icmp_len - icmp_header_len;
        if (payload_len < 28) {
            error = ValidationError::ICMP_TRUNCATED_PAYLOAD;
            return false;
        }


        // invalid ipv4 (structural checks only, no validation of field values)
        const uint8_t* inner_ptr = view.data + icmp_offset + icmp_header_len;
        const IPv4Header* inner = reinterpret_cast<const IPv4Header*>(inner_ptr);

        if ((inner->version_ihl >> 4) != 4) {
            error = ValidationError::ICMP_EMBEDDED_IPV4_INVALID;
            return false;
        }

        uint8_t inner_ihl = inner->version_ihl & 0x0F;
        if (inner_ihl < 5) {
            error = ValidationError::ICMP_EMBEDDED_IPV4_INVALID;
            return false;
        }

        size_t inner_header_len = inner_ihl * 4;
        uint16_t inner_total_len = ntohs(inner->total_length);

        if (inner_total_len < inner_header_len) {
            error = ValidationError::ICMP_EMBEDDED_IPV4_INVALID;
            return false;
        }
    }

    // checksum validation
    uint16_t received = ntohs(icmp->checksum);
    uint8_t temp[65535];
    memcpy(temp, view.data + icmp_offset, icmp_len);
    // zeroing out checksum before computation
    temp[2] = 0;
    temp[3] = 0;
    uint16_t computed = compute_checksum(temp, icmp_len);

    if (computed != received) {
        error = ValidationError::ICMP_INVALID_CHECKSUM;
        return false;
    }
    return true;
}


} // namespace dp::validation