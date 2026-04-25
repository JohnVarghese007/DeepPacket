#include "dp/validation/packet-error.hpp"

namespace dp::validation {

std::string to_string(ValidationError err) {

    switch (err) {
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

        // ICMPv4
        case ValidationError::MISSING_ICMPV4_HEADER: return "ICMPv4: Missing header";
        case ValidationError::TOO_SMALL_FOR_ICMPV4: return "ICMPv4: Too small";
        case ValidationError::ICMPV4_INVALID_TYPE: return "ICMPv4: Invalid type";
        case ValidationError::ICMPV4_INVALID_CODE: return "ICMPv4: Invalid code";
        case ValidationError::ICMPV4_INVALID_CHECKSUM: return "ICMPv4: Invalid checksum";
        case ValidationError::ICMPV4_TRUNCATED_PAYLOAD: return "ICMPv4: Truncated payload";
        case ValidationError::ICMPV4_EMBEDDED_IPV4_INVALID: return "ICMPv4: Embedded IPv4 invalid";

        // IPv4
        case ValidationError::MISSING_IPV4_HEADER: return "IPv4: Missing header";
        case ValidationError::TOO_SMALL_FOR_IPV4: return "IPv4: Too small";
        case ValidationError::INVALID_IPV4_VERSION: return "IPv4: Invalid version";
        case ValidationError::INVALID_IPV4_IHL: return "IPv4: Invalid IHL";
        case ValidationError::INVALID_IPV4_IHL_LENGTH: return "IPv4: IHL length mismatch";
        case ValidationError::INVALID_IPV4_TOTAL_LENGTH: return "IPv4: Invalid total length";
        case ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET: return "IPv4: Total length exceeds packet";
        case ValidationError::IPV4_INVALID_CHECKSUM: return "IPv4: Invalid checksum";
        case ValidationError::IPV4_OPTIONS_TRUNCATED: return "IPv4: Options truncated";
        case ValidationError::IPV4_FRAGMENT_OFFSET_INVALID: return "IPv4: Invalid fragment offset";
        case ValidationError::IPV4_MORE_FRAGMENTS_INVALID: return "IPv4: Invalid MF flag usage";

        // IPv6
        case ValidationError::MISSING_IPV6_HEADER: return "IPv6: Missing header";
        case ValidationError::TOO_SMALL_FOR_IPV6: return "IPv6: Too small";
        case ValidationError::INVALID_IPV6_VERSION: return "IPv6: Invalid version";
        case ValidationError::INVALID_IPV6_PAYLOAD_LENGTH: return "IPv6: Invalid payload length";
        case ValidationError::IPV6_PAYLOAD_EXCEEDS_PACKET: return "IPv6: Payload exceeds packet";
        case ValidationError::IPV6_UNSUPPORTED_NEXT_HEADER: return "IPv6: Unsupported next header";
        case ValidationError::IPV6_HOP_LIMIT_ZERO: return "IPv6: Hop limit is zero";
        case ValidationError::IPV6_EXTENSION_HEADER_PRESENT: return "IPv6: Extension header present";
        case ValidationError::IPV6_EXTENSION_HEADER_UNSUPPORTED: return "IPv6: Unsupported extension header";
        case ValidationError::IPV6_EXTENSION_HEADER_TRUNCATED: return "IPv6: Truncated extension header";

        // ICMPv6
        case ValidationError::ICMPV6_MISSING_HEADER: return "ICMPv6: Missing header";
        case ValidationError::ICMPV6_TOO_SMALL: return "ICMPv6: Too small";
        case ValidationError::ICMPV6_INVALID_TYPE: return "ICMPv6: Invalid type";
        case ValidationError::ICMPV6_INVALID_CODE: return "ICMPv6: Invalid code";
        case ValidationError::ICMPV6_INVALID_CHECKSUM: return "ICMPv6: Invalid checksum";
        case ValidationError::ICMPV6_TRUNCATED_PAYLOAD: return "ICMPv6: Truncated payload";
        case ValidationError::ICMPV6_EMBEDDED_IPV6_INVALID: return "ICMPv6: Embedded IPv6 invalid";
        case ValidationError::ICMPV6_ERROR_MESSAGE_INVALID: return "ICMPv6: Invalid error message format";

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
        case ValidationError::UNSUPPORTED_IP_PROTOCOL: return "Unsupported IP protocol";
    }

    return "Unknown Validation Error";
}

} // namespace dp::validation
