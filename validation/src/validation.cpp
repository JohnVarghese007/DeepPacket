#include "validation.hpp"

#define ETHERNET_HEADER_SIZE 14
#define IPV4_MIN_HEADER_SIZE 20
#define TCP_MIN_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPv4_ETHERTYPE 0x0800

std::vector<ValidationError> validate_packet(const PacketView& view) {

    std::vector<ValidationError> errors;

    // Validate Ethernet header
    if(!validate_ethernet(view)) {
        errors.push_back(ValidationError::TOO_SMALL_FOR_ETHERNET);
        return errors; // Cannot proceed without valid Ethernet header
    }
    // Validate IPv4 header
    if(!validate_ipv4(view)) {
        errors.push_back(ValidationError::TOO_SMALL_FOR_IPV4);
        return errors; // Cannot proceed without valid IPv4 header
    }
    // Validate Layer 4 header based on protocol
    if(view.l4_type == L4Type::TCP) {
        if(!validate_tcp(view)) {
            errors.push_back(ValidationError::TOO_SMALL_FOR_TCP);
        }
    }
    else if(view.l4_type == L4Type::UDP) {
        if(!validate_udp(view)) {
            errors.push_back(ValidationError::TOO_SMALL_FOR_UDP);
        }
    }
    else {
        errors.push_back(ValidationError::UNSUPPORTED_L4_PROTOCOL);
    }

    if(errors.empty()) {
        errors.push_back(ValidationError::NONE);
    }

    return errors;
    


}

bool validate_ethernet(const PacketView& view) {
    // Implementation of Ethernet validation
    size_t ethernet_header_size = 14; // Standard Ethernet header size
    if(view.size() < ethernet_header_size) {
        return false;
    }
    // Check if EtherType is valid for IPv4
    //uint16_t ethertype = 0x0800; // Example EtherType for IPv4
    return true;
}

// Validate IPv4 header
bool validate_ipv4(const PacketView& view) {
    // Implementation of IPv4 validation
    size_t ipv4_header_size = 20; // Minimum IPv4 header size
    if(view.size() < ipv4_header_size) {
        return false;
    }
    // Check IHL, total length, etc.
    return true;
}   

// Validate TCP header
bool validate_tcp(const PacketView& view) {
    // Implementation of TCP validation
    size_t tcp_header_size = 20; // Minimum TCP header size
    if(view.size() < tcp_header_size) {
        return false;
    }
    // Check header size, flags, etc.
    return true;
}

// Validate UDP header
bool validate_udp(const PacketView& view) {
    // Implementation of UDP validation
    size_t udp_header_size = 8; // UDP header size
    if(view.size() < udp_header_size) {
        return false;
    }
    // Check length, checksum, etc.
    return true;
}

