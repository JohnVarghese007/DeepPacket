#include "packet-error.hpp"

std::string to_string(ValidationError err) {
    
    switch(err) {
        case ValidationError::NONE: return "No Errors Found during validation";

        // Ethernet
        case ValidationError::TOO_SMALL_FOR_ETHERNET: return "Ethernet: Too small";
        case ValidationError::INVALID_ETHERTYPE: return "Ethernet: Invalid Ethertype";

        // ARP
        case ValidationError::ARP_TRUNCATED_HEADER: return "ARP: Truncated header";
        case ValidationError::ARP_INVALID_HTYPE: return "ARP: Invalid HTYPE";
        case ValidationError::ARP_INVALID_PTYPE: return "ARP: Invalid PTYPE";
        case ValidationError::ARP_INVALID_HLEN: return "ARP: Invalid HLEN";
        case ValidationError::ARP_INVALID_PLEN: return "ARP: Invalid PLEN";
        case ValidationError::ARP_INVALID_OPCODE: return "ARP: Invalid opcode";
        case ValidationError::ARP_TRUNCATED_ADDRESSES: return "ARP: Truncated addresses";
        case ValidationError::ARP_REPLY_TO_BROADCAST: return "ARP: Reply sent to broadcast";

        // ICMP
        case ValidationError::MISSING_ICMP_HEADER: return "ICMP: Missing header";
        case ValidationError::TOO_SMALL_FOR_ICMP: return "ICMP: Too small";
        case ValidationError::ICMP_INVALID_TYPE: return "ICMP: Invalid type";
        case ValidationError::ICMP_INVALID_CODE: return "ICMP: Invalid code";
        case ValidationError::ICMP_INVALID_CHECKSUM: return "ICMP: Invalid checksum";
        case ValidationError::ICMP_TRUNCATED_PAYLOAD: return "ICMP: Truncated Payload";
        case ValidationError::ICMP_EMBEDDED_IPV4_INVALID: return "ICMP: Embedded IPv4 invalid";

        // IPv4
        case ValidationError::MISSING_IPV4_HEADER: return "IPv4: Missing header";
        case ValidationError::TOO_SMALL_FOR_IPV4: return "IPv4: Too small";
        case ValidationError::INVALID_IPV4_VERSION: return "IPv4: Invalid version";
        case ValidationError::INVALID_IPV4_IHL: return "IPv4: Invalid IHL";
        case ValidationError::INVALID_IPV4_IHL_LENGTH: return "IPv4: IHL length mismatch";
        case ValidationError::INVALID_IPV4_TOTAL_LENGTH: return "IPv4: Invalid total length";
        case ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET: return "IPv4: Total length exceeds packet";
        case ValidationError::IPV4_INVALID_CHECKSUM: return "IPv4: Invalid checksum";

        // TCP
        case ValidationError::MISSING_TCP_HEADER: return "TCP: Missing header";
        case ValidationError::TOO_SMALL_FOR_TCP: return "TCP: Too small";
        case ValidationError::INVALID_TCP_DATA_OFFSET: return "TCP: Invalid data offset";
        case ValidationError::TCP_HEADER_EXCEEDS_PACKET: return "TCP: Header exceeds packet";
        case ValidationError::TCP_INVALID_CHECKSUM: return "TCP: Invalid checksum";

        // UDP
        case ValidationError::MISSING_UDP_HEADER: return "UDP: Missing header";
        case ValidationError::TOO_SMALL_FOR_UDP: return "UDP: Too small";
        case ValidationError::INVALID_UDP_LENGTH: return "UDP: Invalid length";
        case ValidationError::UDP_LENGTH_EXCEEDS_PACKET: return "UDP: Length exceeds packet";
        case ValidationError::UDP_INVALID_CHECKSUM: return "UDP: Invalid checksum";

        // misc errors
        case ValidationError::UNSUPPORTED_L4_PROTOCOL: return "Unsupported L4 Protocol";
    }

    return "Unknown Validation Error";
}
