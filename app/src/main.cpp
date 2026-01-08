#include <iostream>
#include "parser.hpp"
#include "validation.hpp"

// Sample TCP Packet (Ethernet + IPv4 + TCP Headers)
    uint8_t sample_tcp_packet[] = {   // with no payload
        // --- Ethernet Header (14 bytes) ---
        0x00,0x11,0x22,0x33,0x44,0x55,   // Dest MAC
        0x66,0x77,0x88,0x99,0xAA,0xBB,   // Src MAC
        0x08,0x00,                        // EtherType = 0x0800 (IPv4)

        // --- IPv4 Header (20 bytes) ---
        0x45,       // Version/IHL
        0x00,       // DSCP/ECN
        0x00,0x28,  // Total Length = 40 bytes
        0x12,0x34,  // Identification
        0x40,0x00,  // Flags/Fragment Offset (DF set)
        0x40,       // TTL = 64
        0x06,       // Protocol = TCP
        0x00,0x00,  // Header Checksum
        0xC0,0xA8,0x01,0x02,  // Src IP = 192.168.1.2
        0xC0,0xA8,0x01,0x03,  // Dst IP = 192.168.1.3

        // --- TCP Header (20 bytes) ---
        0x04,0xD2,  // Src Port = 1234
        0x00,0x50,  // Dst Port = 80
        0xAB,0xCD,0xEF,0xFF,  // Seq Num
        0x00,0x00,0x00,0x00,  // Ack Num
        0x50,       // Data Offset / Reserved
        0x02,       // Flags = SYN
        0x04,0x00,  // Window = 1024
        0x00,0x00,  // Checksum
        0x00,0x00   // Urgent pointer
    };

    // Sample UDP packet (Ethernet + IPv4 + UDP + payload)
    uint8_t sample_udp_packet[] = {
        // Ethernet (14)
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00, // IPv4

        // IPv4 (20)
        0x45, 0x00, 0x00,0x1C, 0x12,0x34, 0x40,0x00, 0x40, 0x11,
        0x00,0x00, 0xC0,0xA8,0x01,0x02, 0xC0,0xA8,0x01,0x03,

        // UDP (8)
        0x1F,0x90, 0x23,0x28, 0x00,0x08, 0x12,0x34,

        // Payload (0 bytes)
    };

// SAMPLE MALFORMED PACKETS, ONE FOR EACH KIND OF ERROR:
std::vector<std::vector<uint8_t>> malformed_packets = {

    // 0. TOO_SMALL_FOR_ETHERNET (<14 bytes)
    {
        0x00, 0x01, 0x02
    },

    // 1. INVALID_ETHERTYPE (EtherType != 0x0800)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x12,0x34
    },

    // 2. MISSING_IPV4_HEADER (EtherType OK, but <1 byte of IPv4)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00
        // No IPv4 bytes
    },

    // 3. TOO_SMALL_FOR_IPV4 (<14+20 bytes)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // Only 10 bytes of IPv4
        1,2,3,4,5,6,7,8,9,10
    },

    // 4. INVALID_IPV4_VERSION (version=6, full IPv4 header present)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // IPv4 header (20 bytes)
        0x60,0x00,0x00,0x28, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0
    },

    // 5. INVALID_IPV4_IHL (ihl < 5)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // version=4, ihl=1
        0x41,0x00,0x00,0x28, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0
    },

    // 6. INVALID_IPV4_IHL_LENGTH (ihl=6 → 24 bytes needed, only 20 provided)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // version=4, ihl=6
        0x46,0x00,0x00,0x40, 0,0,0,0, 64,6,
        // Only 20 bytes of IPv4 header present
        0,0,0,0,0,0,0,0,0,0,
        // Missing extra 4 bytes required by ihl=6
    },

    // 7. INVALID_IPV4_TOTAL_LENGTH (total_length < header_length)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 16 < 20 header
        0x45,0x00,0x00,0x10, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0
    },

    // 8. IPV4_TOTAL_LENGTH_EXCEEDS_PACKET
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 255 > actual bytes
        0x45,0x00,0x00,0xFF, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0
    },

    // 9. MISSING_TCP_HEADER (strict A1: total_length=20 → no TCP bytes)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // IPv4: total_length=20, protocol=6
        0x45,0x00,0x00,0x14, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0
        // No TCP bytes
    },

    // 10. TOO_SMALL_FOR_TCP (<20 bytes of TCP header)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 30 (20 IP + 10 TCP)
        0x45,0x00,0x00,0x1E, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0,
        // 10 bytes of TCP
        0,0,0,0,0,0,0,0,0,0
    },

    // TCP_HEADER_EXCEEDS_PACKET (valid IPv4, valid TCP offset, header too short)
{
    // Ethernet (14 bytes)
    0,0,0,0,0,0, 0,0,0,0,0,0,
    0x08,0x00,

    // IPv4 header (20 bytes)
    // version=4, ihl=5, total_length=40 (20 IP + 20 TCP), protocol=6
    0x45,0x00, 0x00,0x28,   // total_length = 40
    0x00,0x00, 0x00,0x00,
    64, 6,                 // TTL=64, protocol=TCP
    0x00,0x00,             // checksum
    0,0,0,0,               // src IP
    0,0,0,0,               // dst IP

    // TCP header start (20 bytes provided)
    0x00,0x50,             // src port
    0x01,0xBB,             // dst port
    0x00,0x00,0x00,0x00,   // seq num
    0x00,0x00,0x00,0x00,   // ack num

    // data_offset = 8 (32 bytes required)
    0x80,                  // data_offset = 8
    0x00,                  // flags

    // remaining TCP bytes (to reach 20 total)
    0x00,0x00,             // window
    0x00,0x00,             // checksum
    0x00,0x00              // urgent pointer
}
,


    // 12. INVALID_TCP_DATA_OFFSET (offset=15 → 60 bytes needed)
    {
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        0x45,0x00,0x00,0x28, 0,0,0,0, 64,6,
        0,0,0,0,0,0,0,0,0,0,
        0,0,0,0, 0,0,0,0,
        0xF0,
        0x00,
        0,0,0,0,0,0,0,0,0,0
    },


    // 13. MISSING_UDP_HEADER (strict A1: total_length=20 → no UDP bytes)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // IPv4: total_length=20, protocol=17
        0x45,0x00,0x00,0x14, 0,0,0,0, 64,17,
        0,0,0,0,0,0,0,0,0,0
        // No UDP bytes
    },

    // 14. TOO_SMALL_FOR_UDP (<8 bytes)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 26 (20 IP + 6 UDP)
        0x45,0x00,0x00,0x1A, 0,0,0,0, 64,17,
        0,0,0,0,0,0,0,0,0,0,
        // 6 bytes of UDP
        0,0,0,0,0,0
    },

    // 15. INVALID_UDP_LENGTH (udp_len < 8)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 28 (20 IP + 8 UDP)
        0x45,0x00,0x00,0x1C, 0,0,0,0, 64,17,
        0,0,0,0,0,0,0,0,0,0,
        // UDP header: length = 4
        0x00,0x00, 0x00,0x00, 0x00,0x04, 0x00,0x00
    },

    // 16. UDP_LENGTH_EXCEEDS_PACKET (udp_len > actual bytes)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // total_length = 28 (20 IP + 8 UDP)
        0x45,0x00,0x00,0x1C, 0,0,0,0, 64,17,
        0,0,0,0,0,0,0,0,0,0,
        // UDP header: length = 32 (> 8 bytes available)
        0x00,0x00, 0x00,0x00, 0x00,0x20, 0x00,0x00
    },

    // 17. UNSUPPORTED_L4_PROTOCOL (protocol = 99)
    {
        // Ethernet
        0,0,0,0,0,0, 0,0,0,0,0,0,
        0x08,0x00,
        // IPv4: total_length=20, protocol=99
        0x45,0x00,0x00,0x14, 0,0,0,0, 64,99,
        0,0,0,0,0,0,0,0,0,0
    }
};

std::vector<std::string> expected_errors = {
    "TOO_SMALL_FOR_ETHERNET",
    "INVALID_ETHERTYPE",
    "MISSING_IPV4_HEADER",
    "TOO_SMALL_FOR_IPV4",
    "INVALID_IPV4_VERSION",
    "INVALID_IPV4_IHL",
    "INVALID_IPV4_IHL_LENGTH",
    "INVALID_IPV4_TOTAL_LENGTH",
    "IPV4_TOTAL_LENGTH_EXCEEDS_PACKET",
    "MISSING_TCP_HEADER",
    "TOO_SMALL_FOR_TCP",
    "TCP_HEADER_EXCEEDS_PACKET",   // <-- swapped
    "INVALID_TCP_DATA_OFFSET",
    "MISSING_UDP_HEADER",
    "TOO_SMALL_FOR_UDP",
    "INVALID_UDP_LENGTH",
    "UDP_LENGTH_EXCEEDS_PACKET",
    "UNSUPPORTED_L4_PROTOCOL"
};



int main() {
    std::cout << "\n=== TCP PACKET PARSING  ===" << std::endl;
    ParsedPacket tcp = parse_packet(std::span<const uint8_t>(sample_tcp_packet));
    tcp.view.print();
    std::cout << "\n=== Validation for TCP packet  ===" << std::endl;
    PacketValidator tcp_validator(tcp.view);
    tcp_validator.print_errors();
    std::cout << "\n============================\n" <<std::endl;

    std::cout << "\n=== UDP PACKET PARSING ===" << std::endl;
    ParsedPacket udp = parse_packet(std::span<const uint8_t>(sample_udp_packet));
    udp.view.print();
    std::cout << "\n=== Validation for UDP packet  ===" << std::endl;
    PacketValidator udp_validator(udp.view);
    udp_validator.print_errors();
    std::cout << "\n============================\n" <<std::endl;

    std::cout << "\n=== MALFORMED PACKET TESTS ===" << std::endl;
    for(size_t i = 0; i < malformed_packets.size(); i++) {
        std::cout << " Malformed Packet Test: " << i << " " << std::endl;
        ParsedPacket packet = parse_packet(std::span<const uint8_t>(malformed_packets[i]));
        packet.view.print();
        std::cout << "\n=== Validation for malformed packet " << i << " ===" << std::endl;
        std::cout << "\nExpected error: " << expected_errors[i] << " \n" << std::endl;
        PacketValidator validator(packet.view);
        validator.print_errors();
    }
    std::cout << "\n============================\n" <<std::endl;

    return 0;
}
