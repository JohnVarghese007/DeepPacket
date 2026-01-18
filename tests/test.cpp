#include <iostream>
#include "parser.hpp"
#include "validation.hpp"
#include "raw-capture.hpp"

// Sample TCP Packet (Ethernet + IPv4 + TCP Headers)
std::vector<uint8_t> tcp_valid = {

    // =======================
    // ETHERNET HEADER (14 B)
    // =======================
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,   // Destination MAC
    0x11,0x22,0x33,0x44,0x55,0x66,   // Source MAC
    0x08,0x00,                       // EtherType = IPv4 (0x0800)

    // =======================
    // IPv4 HEADER (20 B)
    // =======================
    0x45,                            // Version=4, IHL=5 (20 bytes)
    0x00,                            // DSCP/ECN
    0x00,0x2C,                       // Total Length = 44 bytes (20 IP + 20 TCP + 4 payload)
    0x00,0x01,                       // Identification
    0x00,0x00,                       // Flags + Fragment Offset
    0x40,                            // TTL = 64
    0x06,                            // Protocol = TCP (6)
    0xF9,0x77,                       // IPv4 Header Checksum (VALID)
    0xC0,0xA8,0x00,0x01,             // Source IP = 192.168.0.1
    0xC0,0xA8,0x00,0x02,             // Destination IP = 192.168.0.2

    // =======================
    // TCP HEADER (20 B)
    // =======================
    0x00,0x50,                       // Source Port = 80
    0x01,0xBB,                       // Destination Port = 443
    0x00,0x00,0x00,0x00,             // Sequence Number
    0x00,0x00,0x00,0x00,             // Acknowledgment Number
    0x50,                            // Data Offset=5 (20 bytes), Reserved=0
    0x02,                            // Flags = SYN
    0x20,0x00,                       // Window Size
    0x08,0x6E,                       // TCP Checksum (VALID)
    0x00,0x00,                       // Urgent Pointer

    // =======================
    // PAYLOAD (4 B)
    // =======================
    0x01,0x02,0x03,0x04              // Arbitrary payload
};
 

// Sample UDP packet (Ethernet + IPv4 + UDP + payload)
std::vector<uint8_t> udp_valid = {

    // =======================
    // ETHERNET HEADER (14 B)
    // =======================
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,   // Destination MAC
    0x11,0x22,0x33,0x44,0x55,0x66,   // Source MAC
    0x08,0x00,                       // EtherType = IPv4 (0x0800)

    // =======================
    // IPv4 HEADER (20 B)
    // =======================
    0x45,                            // Version=4, IHL=5 (20 bytes)
    0x00,                            // DSCP/ECN
    0x00,0x20,                       // Total Length = 32 bytes (20 IP + 8 UDP + 4 payload)
    0x00,0x02,                       // Identification
    0x00,0x00,                       // Flags + Fragment Offset
    0x40,                            // TTL = 64
    0x11,                            // Protocol = UDP (17)
    0xF9,0x77,                       // IPv4 Header Checksum (VALID)
    0xC0,0xA8,0x00,0x01,             // Source IP = 192.168.0.1
    0xC0,0xA8,0x00,0x02,             // Destination IP = 192.168.0.2

    // =======================
    // UDP HEADER (8 B)
    // =======================
    0x13,0x89,                       // Source Port = 5001
    0x13,0x8A,                       // Destination Port = 5002
    0x00,0x0C,                       // Length = 12 bytes (8 header + 4 payload)
    0x53,0x69,                       // UDP Checksum (VALID)

    // =======================
    // PAYLOAD (4 B)
    // =======================
    0x01,0x02,0x03,0x04              // Arbitrary payload
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


// SAMPLE  CHECKSUM PACKETS, ONE FOR EACH KIND OF ERROR:
std::vector<std::vector<uint8_t>> checksum_packets = {

    // 0. VALID TCP
    {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x11,0x22,0x33,0x44,0x55,0x66,
        0x08,0x00,

        0x45,0x00,0x00,0x2C,
        0x00,0x01,0x00,0x00,
        0x40,0x06,0xF9,0x77,   // FIXED IPv4 checksum 0x40,0x06,0xF9,0x77,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,

        0x00,0x50,0x01,0xBB,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00,
        0x08,0x6E,             // FIXED TCP checksum
        0x00,0x00,

        0x01,0x02,0x03,0x04
    },

    // 1. INVALID TCP
    {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x11,0x22,0x33,0x44,0x55,0x66,
        0x08,0x00,

        0x45,0x00,0x00,0x2C,
        0x00,0x01,0x00,0x00,
        0x40,0x06,0xF9,0x77,   // FIXED IPv4 checksum
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,

        0x00,0x50,0x01,0xBB,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00,
        0x00,0x00,             // BAD TCP checksum
        0x00,0x00,

        0x01,0x02,0x03,0x04
    },

    // 2. VALID UDP
    {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x11,0x22,0x33,0x44,0x55,0x66,
        0x08,0x00,

        0x45,0x00,0x00,0x20,
        0x00,0x02,0x00,0x00,
        0x40,0x11,0xF9,0x77,   // FIXED IPv4 checksum 0x40,0x11,0xF9,0x77,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,

        0x13,0x89,0x13,0x8A,
        0x00,0x0C,
        0x53,0x69,             // VALID UDP checksum

        0x01,0x02,0x03,0x04
    },

    // 3. INVALID UDP
    {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x11,0x22,0x33,0x44,0x55,0x66,
        0x08,0x00,

        0x45,0x00,0x00,0x20,
        0x00,0x02,0x00,0x00,
        0x40,0x11,0xF9,0x77,   // FIXED IPv4 checksum
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,

        0x13,0x89,0x13,0x8A,
        0x00,0x0C,
        0x00,0x00,             // BAD UDP checksum

        0x01,0x02,0x03,0x04
    }
};



// ARP PACKETS
std::vector<uint8_t> arp_valid_request = {
    // Ethernet
    0x11,0x22,0x33,0x44,0x55,0x66,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x08,0x06,

    // ARP header
    0x00,0x01,        // HTYPE = Ethernet
    0x08,0x00,        // PTYPE = IPv4
    0x06,             // HLEN
    0x04,             // PLEN
    0x00,0x01,        // Opcode = Request

    // Sender MAC
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    // Sender IP
    0x0A,0x00,0x00,0x01,
    // Target MAC
    0x00,0x00,0x00,0x00,0x00,0x00,
    // Target IP
    0x0A,0x00,0x00,0x02
};

std::vector<uint8_t> arp_valid_reply = {
    // Ethernet
    0x11,0x22,0x33,0x44,0x55,0x66,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x08,0x06,

    // ARP header
    0x00,0x01,
    0x08,0x00,
    0x06,
    0x04,
    0x00,0x02,        // Opcode = Reply

    // Sender MAC
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    // Sender IP
    0x0A,0x00,0x00,0x02,
    // Target MAC
    0x11,0x22,0x33,0x44,0x55,0x66,
    // Target IP
    0x0A,0x00,0x00,0x01
};



// BASELINE PARSING + VALIDATION CHECKS
void baseline() {
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
}


// CHECKSUM TESTS
void checksum_test() {
    std::cout << "\n=== MALFORMED PACKET TESTS FOR CHECKSUM ===" << std::endl;
    for(size_t i = 0; i < checksum_packets.size(); i++) {
        std::cout << " Malformed Packet Test: " << i << " " << std::endl;

        // Print raw IPv4 checksum bytes from the vector
        std::cout << "Vector IPv4 checksum bytes: "
              << std::hex
              << (int)checksum_packets[i][14 + 10] << " "
              << (int)checksum_packets[i][14 + 11]
              << std::dec << std::endl;

        ParsedPacket packet = parse_packet(std::span<const uint8_t>(checksum_packets[i]));

        packet.view.print();

        // Print raw IPv4 checksum bytes actually parsed
        if (packet.view.has_ip) {
            const IPv4Header* iph = packet.view.ip_layer.iph;
            std::cout << "Parsed IPv4 checksum bytes: "
                  << std::hex
                  << ((iph->header_checksum >> 8) & 0xFF) << " "
                  << (iph->header_checksum & 0xFF)
                  << std::dec << std::endl;
        }

        std::cout << "\n=== Validation for malformed packet " << i << " ===" << std::endl;    
        PacketValidator validator(packet.view);
        validator.print_errors();

        std::cout << "----------------------------------------\n";
    }

    std::cout << "\n============================\n" <<std::endl;

}



// ARP TESTS
void arp_tests() {
    std::vector<std::vector<uint8_t>> arp_packets;
    // valid arp req (ValidationError::NONE)
    arp_packets.push_back(arp_valid_request);
    arp_packets.push_back(arp_valid_reply);
    std::cout << "arp_valid_request size = " << arp_valid_request.size() << "\n";
    std::cout << "arp_valid_reply size = " << arp_valid_reply.size() << "\n";


    // invalid htype
    std::vector<uint8_t> arp_invalid_htype = arp_valid_request;
    arp_invalid_htype[14] = 0x00;
    arp_invalid_htype[15] = 0x02;   // HTYPE = 2 (not Ethernet)
    arp_packets.push_back(arp_invalid_htype);

    // invalid ptype
    std::vector<uint8_t> arp_invalid_ptype = arp_valid_request;
    arp_invalid_ptype[16] = 0x12;
    arp_invalid_ptype[17] = 0x34;   // PTYPE = 0x1234
    arp_packets.push_back(arp_invalid_ptype);

    // invalid hlen
    std::vector<uint8_t> arp_invalid_hlen = arp_valid_request;
    arp_invalid_hlen[18] = 0x05;    // HLEN = 5 (should be 6)
    arp_packets.push_back(arp_invalid_hlen);

    // invalid plen
    std::vector<uint8_t> arp_invalid_plen = arp_valid_request;
    arp_invalid_plen[19] = 0x05;    // PLEN = 5 (should be 4)
    arp_packets.push_back(arp_invalid_plen);

    // invalid opcode
    std::vector<uint8_t> arp_invalid_opcode = arp_valid_request;
    arp_invalid_opcode[20] = 0x12;
    arp_invalid_opcode[21] = 0x34;  // Opcode = 0x1234
    arp_packets.push_back(arp_invalid_opcode);

    // truncated header
    std::vector<uint8_t> arp_truncated_header = {
        0x11,0x22,0x33,0x44,0x55,0x66,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x08,0x06,
        0x00,0x01,0x08,0x00 // stops early
    };
    arp_packets.push_back(arp_truncated_header);

    // truncated addresses
    std::vector<uint8_t> arp_truncated_addresses = arp_valid_request;

    size_t arp_offset = 14; // 14
    size_t target_mac_offset = arp_offset + offsetof(ARPHeader, target_mac);
    size_t cut = target_mac_offset + 2;
    arp_truncated_addresses.resize(cut);
    arp_packets.push_back(arp_truncated_addresses);



    // reply to broadcast
    std::vector<uint8_t> arp_reply_broadcast = arp_valid_reply;
    for (int i = 0; i < 6; i++) {
        arp_reply_broadcast[32 + i] = 0xFF;  // target MAC = FF:FF:FF:FF:FF:FF
    }
    arp_packets.push_back(arp_reply_broadcast);

    std::cout << "\nARP PACKET TESTS\n"  << std::endl;
    for(size_t i = 0; i < arp_packets.size(); i++) {
        std::cout << "\n=== Test " << i << " ===" << std::endl;
        ParsedPacket packet = parse_packet(std::span<const uint8_t>(arp_packets[i]));
        packet.view.print();
        std::cout << "\n=== Validation for  packet " << i << " ===" << std::endl;
        PacketValidator packet_validator(packet.view);
        packet_validator.print_errors();
        std::cout << "\n============================\n" <<std::endl;
    }

}



// RAW CAPTURE TEST
int raw_capture_test(){
    SocketCapture capture;

    if (!capture.valid()) {
        std::cerr << "Raw socket capture failed.\n";
        return 1;
    }

    constexpr std::size_t MAX_FRAME_SIZE = 65536;
    std::vector<uint8_t> buffer(MAX_FRAME_SIZE);

    int captured = 0;

    while (captured < 10) {
        ssize_t bytes = capture.read_frame(buffer.data(), buffer.size());

        if (bytes <= 0) {
            continue;
        }

        std::cout << "\n=== Packet " << captured
                  << " (" << bytes << " bytes) ===\n";

        ParsedPacket packet = parse_packet(
            std::span<const uint8_t>(buffer.data(), bytes)
        );

        packet.view.print();

        PacketValidator validator(packet.view);
        validator.print_errors();

        captured++;
    }

    std::cout << "\nCaptured and processed 10 packets.\n";
    return 0;
}


void run_ethernet_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    ostringstream oss;

    // valid ethernet
    tests.push_back({tcp_valid, ValidationError::NONE});

    // invalid ethertype
    std::vector<uint8_t> invalid_ethertype_packet = tcp_valid;
    invalid_ethertype_packet[12] = 0x12;
    invalid_ethertype_packet[13] = 0x34;
    tests.push_back({invalid_ethertype_packet, ValidationError::INVALID_ETHERTYPE});

    // ethernet too small
    std::vector<uint8_t> too_small = {0x00, 0x01, 0x02};
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_ETHERNET});

    oss << "\n==== ARP TESTS ====\n"  << std::endl;
    for(size_t i = 0; i < tests.size(); i++) {
        oss << "\n=== Test " << i + 1 << " ===" << std::endl;
        std::vector<uint8_t> packet = tests[i].first;
        ValidationError err = tests[i].second;
        ParsedPacket packet = parse_packet(std::span<const uint8_t>(packet));
        packet.view.print();
        std::cout << "\n=== Validation for  packet " << i << " ===" << std::endl;
        PacketValidator packet_validator(packet.view);
        packet_validator.print_errors();
        std::cout << "\n============================\n" <<std::endl;
    }
    std::cout << oss.str() << std::endl;
}

void run_arp_tests() {
    ostringstream oss;
    std::cout << oss.str() << std::endl;
}

void run_ipv4_tests() {
    ostringstream oss;
    std::cout << oss.str() << std::endl;
}

void run_tcp_tests() {
    ostringstream oss;
    std::cout << oss.str() << std::endl;
}

void run_udp_tests() {
    ostringstream oss;
    std::cout << oss.str() << std::endl;
}

int main() {

    run_ethernet_tests();
    run_arp_tests();
    run_ipv4_tests();
    run_tcp_tests();
    run_udp_tests();
    // run_icmp_tests();
    // baseline(); -> Depracated must fix checksums
    // checksum_test();

    // arp_tests();

    /* RAW CAPTURE TEST
    int res = raw_capture_test();    
    if(res!= 0){
        return 1;
    }
    */
    return 0;
}
