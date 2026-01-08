#include "validation.hpp"
#include <iostream>
#include <cstddef>
#include <cstdint>
#include <string>
#include <arpa/inet.h>

#define ETHERNET_HEADER_SIZE 14
#define IPV4_MIN_HEADER_SIZE 20
#define TCP_MIN_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPv4_ETHERTYPE 0x0800


void  PacketValidator::validate_packet() {
  
    ValidationError err;
    errors.clear();

    // Layer 2: Ethernet Validation
    if (!validate_ethernet(view, err)) {
        errors.push_back(err);
        return;
    }

    // Layer 3: IPv4 Validation
    if (!validate_ipv4(view, err)) {
        errors.push_back(err);
        return;
    }

    // Layer 4 Protocols based on l4_type
    switch (view.l4_type) {
        case L4Type::TCP:
            if (!validate_tcp(view, err))
                errors.push_back(err);
            break;

        case L4Type::UDP:
            if (!validate_udp(view, err))
                errors.push_back(err);
            break;

        default:
            errors.push_back(ValidationError::UNSUPPORTED_L4_PROTOCOL);
            break;
    }

    // If there are no errors add a NONE flag to show that validation was completed with no errors
    // Lack of a NONE flag with no other errors means validation was never done
    if (errors.empty())
        errors.push_back(ValidationError::NONE);

    return;
}

/*
    **** supported errors ***

    NONE,
    TOO_SMALL_FOR_ETHERNET,
    INVALID_ETHERTYPE,
    MISSING_IPV4_HEADER,
    TOO_SMALL_FOR_IPV4,
    INVALID_IPV4_VERSION,
    INVALID_IPV4_IHL,
    INVALID_IPV4_IHL_LENGTH,
    INVALID_IPV4_TOTAL_LENGTH,
    IPV4_TOTAL_LENGTH_EXCEEDS_PACKET,
    MISSING_TCP_HEADER,
    TOO_SMALL_FOR_TCP,
    INVALID_TCP_DATA_OFFSET,
    TCP_HEADER_EXCEEDS_PACKET,
    MISSING_UDP_HEADER,
    TOO_SMALL_FOR_UDP,
    INVALID_UDP_LENGTH,
    UDP_LENGTH_EXCEEDS_PACKET,    
    UNSUPPORTED_L4_PROTOCOL
*/
void PacketValidator::print_errors() const {
    for(ValidationError err: errors) {
        switch(err) {

            case ValidationError::TOO_SMALL_FOR_ETHERNET:
                std::cout << "Too small for Ethernet" << std::endl;
                break;

            case ValidationError::INVALID_ETHERTYPE:
                std::cout << "Invalid Ethertype" << std::endl;
                break;

            case ValidationError::MISSING_IPV4_HEADER:
                std::cout << "Missing IPv4 header" << std::endl;
                break;

            case ValidationError::TOO_SMALL_FOR_IPV4:
                std::cout << "Too small for IPv4" << std::endl;
                break;
            
            case ValidationError::INVALID_IPV4_VERSION:
                std::cout << "Invalid IPv4 version" << std::endl;
                break;

            case ValidationError::INVALID_IPV4_IHL:
                std::cout << "Invalid IPv4 IHL" << std::endl;
                break;

            case ValidationError::INVALID_IPV4_IHL_LENGTH:
                std::cout << "Invalid IPv4 IHL length" << std::endl;
                break;

            case ValidationError::INVALID_IPV4_TOTAL_LENGTH:
                std::cout << "Invalid IPv4 Total length" << std::endl;
                break;

            case ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET:
                std::cout << "IPv4 total length exceeds packet" << std::endl;
                break;
            
            case  ValidationError::MISSING_TCP_HEADER:
                std::cout << "Missing TCP Header" << std::endl;
                break;

            case ValidationError::TOO_SMALL_FOR_TCP:
                std::cout << "Too small for TCP" << std::endl;
                break;

            case ValidationError::INVALID_TCP_DATA_OFFSET:
                std::cout << "Invalid TCP data offset" << std::endl;
                break;

            case ValidationError::TCP_HEADER_EXCEEDS_PACKET:
                std::cout << "TCP header exceeds packet" << std::endl;
                break;
            
            case ValidationError::MISSING_UDP_HEADER:
                std::cout << "Missing UDP header" << std::endl;
                break;

            case ValidationError::TOO_SMALL_FOR_UDP:
                std::cout << "Too small for UDP" << std::endl;
                break;

            case ValidationError::INVALID_UDP_LENGTH:
                std::cout << "Invalid UDP length" << std::endl;
                break;

            case ValidationError::UDP_LENGTH_EXCEEDS_PACKET:
                std::cout << "UDP length exceeds packet" << std::endl;
                break;

            case ValidationError::UNSUPPORTED_L4_PROTOCOL:
                std::cout << "Unsupported L4 Protocol" << std::endl;
                break;
            
            case ValidationError::NONE:
                std::cout << "No errors found during Validation" << std::endl;
                break;

            default:
                std::cout << "Unsupported Error!" << std::endl;
                std::cout << "Verify error and validation module design" << std::endl;
                break;
        }
    }

    // if there are no errors, not even NONE, that means validation never happened
    if(errors.empty()){
        std::cout << "Error in Validation module" <<  std::endl;
        std::cout << "Looks like validation never happened" << std::endl;
    }
}



bool PacketValidator::validate_ethernet(const PacketView& view, ValidationError& error) {
    if (view.size() < ETHERNET_HEADER_SIZE) {
        error = ValidationError::TOO_SMALL_FOR_ETHERNET;
        return false;
    }

    // EtherType must be IPv4 for now
    uint16_t ethertype = ntohs(view.eth_layer.eth->ether_type);
    if (ethertype != IPv4_ETHERTYPE) {
        error = ValidationError::INVALID_ETHERTYPE;
        return false;
    }

    return true;
}



// Validate IPv4 header
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

    // Total length must not exceed actual packet size
    if(total_len > view.size() -  ETHERNET_HEADER_SIZE) {
        error = ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET;
        return false;
    }

    return true;
}


// Validate TCP 
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

    return true;
}


// Validate UDP header
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

    return true;
}


