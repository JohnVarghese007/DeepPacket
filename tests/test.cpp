#include <iostream>
#include <iomanip>
#include <sstream>
#include "parser.hpp"
#include "validation.hpp"
#include "raw-capture.hpp"
#include "packet_builder.hpp"



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
    0xF7,0x85,                       // TCP Checksum (VALID)
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
    0xAC,0x96,                       // UDP Checksum (VALID)

    // =======================
    // PAYLOAD (4 B)
    // =======================
    0x01,0x02,0x03,0x04              // Arbitrary payload
};



// Sample ARP Request (Ethernet + ARP Header)
std::vector<uint8_t> arp_valid = {

    // =======================
    // ETHERNET HEADER (14 B)
    // =======================
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,   // Destination MAC = Broadcast
    0x11,0x22,0x33,0x44,0x55,0x66,   // Source MAC
    0x08,0x06,                       // EtherType = ARP (0x0806)

    // =======================
    // ARP HEADER (28 B)
    // =======================
    0x00,0x01,                       // Hardware Type = Ethernet (1)
    0x08,0x00,                       // Protocol Type = IPv4 (0x0800)
    0x06,                            // Hardware Size = 6
    0x04,                            // Protocol Size = 4
    0x00,0x01,                       // Opcode = Request (1)

    // Sender MAC + Sender IP
    0x11,0x22,0x33,0x44,0x55,0x66,   // Sender MAC
    0xC0,0xA8,0x00,0x01,             // Sender IP = 192.168.0.1

    // Target MAC + Target IP
    0x00,0x00,0x00,0x00,0x00,0x00,   // Target MAC = Unknown
    0xC0,0xA8,0x00,0x02              // Target IP = 192.168.0.2
};



// Sample ICMP Echo Request (Ethernet + IPv4 + ICMP)
std::vector<uint8_t> icmp_valid = {

    // =======================
    // ETHERNET HEADER (14 B)
    // =======================
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,   // Destination MAC
    0x11,0x22,0x33,0x44,0x55,0x66,   // Source MAC
    0x08,0x00,                       // EtherType = IPv4 (0x0800)

    // =======================
    // IPv4 HEADER (20 B)
    // =======================
    0x45,                            // Version=4, IHL=5
    0x00,                            // DSCP/ECN
    0x00,0x1C,                       // Total Length = 28 bytes (20 IP + 8 ICMP)
    0x00,0x01,                       // Identification
    0x00,0x00,                       // Flags + Fragment Offset
    0x40,                            // TTL = 64
    0x01,                            // Protocol = ICMP (1)
    0x00,0x00,                       // IPv4 Checksum (will fix below)
    0xC0,0xA8,0x00,0x01,             // Source IP
    0xC0,0xA8,0x00,0x02,             // Destination IP

    // =======================
    // ICMP HEADER (8 B)
    // =======================
    0x08,                            // Type = 8 (Echo Request)
    0x00,                            // Code = 0
    0x00,0x00,                       // Checksum (will fix below)
    0x12,0x34,                       // Identifier
    0x00,0x01                        // Sequence Number
};



// HELPER METHODS
void fix_ipv4_total_length(std::vector<uint8_t>& pkt) {
    uint16_t new_total = pkt.size() - 14; // subtract Ethernet header
    pkt[16] = (new_total >> 8) & 0xFF;
    pkt[17] = new_total & 0xFF;
}



void fix_ipv4_checksum(std::vector<uint8_t>& pkt) {
    uint8_t* ip = &pkt[14];

    // Zero checksum field
    ip[10] = 0;
    ip[11] = 0;

    // Compute checksum over IHL * 4 bytes
    uint8_t ihl = ip[0] & 0x0F;
    size_t header_len = ihl * 4;

    uint16_t sum = compute_checksum(ip, header_len);

    ip[10] = (sum >> 8) & 0xFF;
    ip[11] = sum & 0xFF;
}



void run_single_test(std::ostringstream& oss, int test_no, const std::vector<uint8_t>& packet, ValidationError expected) {
    ParsedPacket parsed = parse_packet(std::span<const uint8_t>(packet));
    PacketValidator validator(parsed.view);

    // Not needed for summary table, maybe can add an explicit flag or smth for this
    // validator.print_errors(oss);

    ValidationError received = validator.errors.empty() ? ValidationError::NONE : validator.errors[0];
    bool pass = (received == expected);

    oss << std::left
        << std::setw(8)   << test_no
        << std::setw(40)  << to_string(expected)
        << std::setw(40)  << to_string(received)
        << (pass ? "PASS" : "FAIL")
        << "\n";

}


// TESTS
void run_ethernet_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid packet using PacketBuilder
    uint8_t src_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    uint8_t src_ip[4] = {192,168,0,1};
    uint8_t dst_ip[4] = {192,168,0,2};

    std::vector<uint8_t> tcp_valid_packet =
        PacketBuilder::build_tcp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            80,                     // src port
            443,                    // dest port
            {0x01,0x02,0x03,0x04}   // payload
        );


    // valid tcp packet
    tests.push_back({tcp_valid_packet, ValidationError::NONE});

    // invalid ethertype
    std::vector<uint8_t> invalid_ethertype = tcp_valid_packet;
    invalid_ethertype[12] = 0x12;
    invalid_ethertype[13] = 0x34;
    tests.push_back({invalid_ethertype, ValidationError::INVALID_ETHERTYPE});

    // too small for ethernet
    std::vector<uint8_t> too_small = {0x00, 0x01, 0x02};
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_ETHERNET});


    oss << "\n==== ETHERNET TESTS ====\n" << std::endl;
    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";

    for (size_t i = 0; i < tests.size(); i++)    {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }

    oss << "\n=======================\n" << std::endl;
    std::cout << oss.str();
}



void run_arp_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid reply packet using PacketBuilder
    // Example MAC/IPs
    uint8_t src_mac[6]     = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac_req[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // broadcast for request
    uint8_t dst_mac_rep[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}; // target MAC for reply

    uint8_t sender_ip[4]   = {192,168,0,1};
    uint8_t target_ip[4]   = {192,168,0,2};

    uint8_t zero_mac[6]    = {0,0,0,0,0,0};

    // --- Valid ARP Request (who-has 192.168.0.2?) ---
    std::vector<uint8_t> arp_request = PacketBuilder::build_arp_packet(
        src_mac,            // Ethernet src
        dst_mac_req,        // Ethernet dst (broadcast)
        src_mac,            // Sender MAC
        sender_ip,          // Sender IP
        zero_mac,           // Target MAC (unknown)
        target_ip,          // Target IP
        1                   // Opcode = request
    );
    tests.push_back({arp_request, ValidationError::NONE});

    // --- Valid ARP Reply (192.168.0.2 is at AA:BB:CC:DD:EE:FF) ---
    std::vector<uint8_t> arp_reply = PacketBuilder::build_arp_packet(
        dst_mac_rep,        // Ethernet src (the replier)
        src_mac,            // Ethernet dst (the original requester)
        dst_mac_rep,        // Sender MAC (the replier’s MAC)
        target_ip,          // Sender IP (192.168.0.2)
        src_mac,            // Target MAC (the requester’s MAC)
        sender_ip,          // Target IP (192.168.0.1)
        2                   // Opcode = reply
    );
    tests.push_back({arp_reply, ValidationError::NONE});

    // invalid htype
    std::vector<uint8_t> arp_invalid_htype = arp_request;
    arp_invalid_htype[14] = 0x00;
    arp_invalid_htype[15] = 0x02;   // HTYPE = 2 (not Ethernet)
    tests.push_back({arp_invalid_htype, ValidationError::ARP_INVALID_HTYPE});

    // invalid ptype
    std::vector<uint8_t> arp_invalid_ptype = arp_request;
    arp_invalid_ptype[16] = 0x12;
    arp_invalid_ptype[17] = 0x34;   // PTYPE = 0x1234
    tests.push_back({arp_invalid_ptype, ValidationError::ARP_INVALID_PTYPE});

    // invalid hlen
    std::vector<uint8_t> arp_invalid_hlen = arp_request;
    arp_invalid_hlen[18] = 0x05;    // HLEN = 5 (should be 6)
    tests.push_back({arp_invalid_hlen, ValidationError::ARP_INVALID_HLEN});

    // invalid plen
    std::vector<uint8_t> arp_invalid_plen = arp_request;
    arp_invalid_plen[19] = 0x05;    // PLEN = 5 (should be 4)
    tests.push_back({arp_invalid_plen, ValidationError::ARP_INVALID_PLEN});

    // invalid opcode
    std::vector<uint8_t> arp_invalid_opcode = arp_request;
    arp_invalid_opcode[20] = 0x12;
    arp_invalid_opcode[21] = 0x34;  // Opcode = 0x1234
    tests.push_back({arp_invalid_opcode, ValidationError::ARP_INVALID_OPCODE});

    // truncated header
    std::vector<uint8_t> arp_truncated_header = {
        0x11,0x22,0x33,0x44,0x55,0x66,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x08,0x06,
        0x00,0x01,0x08,0x00 
    };
    tests.push_back({arp_truncated_header, ValidationError::ARP_TRUNCATED_HEADER});

    // truncated addresses
    std::vector<uint8_t> arp_truncated_addresses = arp_request;

    size_t arp_offset = 14; // 14
    size_t target_mac_offset = arp_offset + offsetof(ARPHeader, target_mac);
    size_t cut = target_mac_offset + 2;
    arp_truncated_addresses.resize(cut);
    tests.push_back({arp_truncated_addresses, ValidationError::ARP_TRUNCATED_ADDRESSES});


    // reply to broadcast
    std::vector<uint8_t> arp_reply_broadcast = arp_reply;
    for (int i = 0; i < 6; i++) {
        arp_reply_broadcast[32 + i] = 0xFF;  // target MAC = FF:FF:FF:FF:FF:FF
    }
    tests.push_back({arp_reply_broadcast, ValidationError::ARP_REPLY_TO_BROADCAST});


    oss << "\n==== ARP TESTS ====\n" << std::endl;

    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";


    for (size_t i = 0; i < tests.size(); i++)    {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }

    oss << "\n=======================\n" << std::endl;
    std::cout << oss.str();
}



void run_ipv4_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid packet(TCP) using PacketBuilder
    uint8_t src_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    uint8_t src_ip[4] = {192,168,0,1};
    uint8_t dst_ip[4] = {192,168,0,2};

    std::vector<uint8_t> valid_packet =
        PacketBuilder::build_tcp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            80,                     // src port
            443,                    // dest port
            {0x01,0x02,0x03,0x04}   // payload
        );


    // valid ipv4 packet
    tests.push_back({valid_packet, ValidationError::NONE});

    // missing ipv4 header
    std::vector<uint8_t> missing_header = valid_packet;
    missing_header.resize(14); // ethernet header size is always 14 bytes
    tests.push_back({missing_header, ValidationError::MISSING_IPV4_HEADER});

    // too small for ipv4
    std::vector<uint8_t> too_small = valid_packet;
    too_small.resize(14 + 10); // < 20 bytes
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_IPV4});

    // invalid version (set version to 6)
    std::vector<uint8_t> invalid_version = valid_packet;
    invalid_version[14] = (6 << 4) | (invalid_version[14] & 0x0F);
    tests.push_back({invalid_version, ValidationError::INVALID_IPV4_VERSION});

    // invalid IHL (< 5)
    std::vector<uint8_t> invalid_ihl = valid_packet;
    invalid_ihl[14] = (4 << 4) | 4; // IHL = 4 (16 bytes)
    tests.push_back({invalid_ihl, ValidationError::INVALID_IPV4_IHL});

    // invalid IHL length (header length > packet size)
    std::vector<uint8_t> invalid_ihl_len = valid_packet;
    invalid_ihl_len[14] = (4 << 4) | 15; // IHL = 15 (60 bytes)
    invalid_ihl_len.resize(14 + 40);     // truncate so it's too short
    tests.push_back({invalid_ihl_len, ValidationError::INVALID_IPV4_IHL_LENGTH});

    // invalid total length (< header length)
    std::vector<uint8_t> invalid_total_len = valid_packet;
    invalid_total_len[16] = 0x00;
    invalid_total_len[17] = 0x10; // total length = 16
    tests.push_back({invalid_total_len, ValidationError::INVALID_IPV4_TOTAL_LENGTH});

    // total length exceeds packet size
    std::vector<uint8_t> total_len_exceeds = valid_packet;
    total_len_exceeds[16] = 0xFF;
    total_len_exceeds[17] = 0xFF; // absurdly large
    tests.push_back({total_len_exceeds, ValidationError::IPV4_TOTAL_LENGTH_EXCEEDS_PACKET});

    // invalid checksum (flip a byte in header)
    std::vector<uint8_t> invalid_checksum = valid_packet;
    invalid_checksum[20] ^= 0xFF; // corrupt source IP
    tests.push_back({invalid_checksum, ValidationError::IPV4_INVALID_CHECKSUM});


    oss << "\n==== IPV4 TESTS ====\n" << std::endl;

    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";

    for (size_t i = 0; i < tests.size(); i++)    {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }

    oss << "\n=======================\n" << std::endl;

    std::cout << oss.str();
}




void run_tcp_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid packet(TCP) using PacketBuilder
    uint8_t src_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    uint8_t src_ip[4] = {192,168,0,1};
    uint8_t dst_ip[4] = {192,168,0,2};

    std::vector<uint8_t> valid_packet =
        PacketBuilder::build_tcp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            80,                     // src port
            443,                    // dest port
            {0x01,0x02,0x03,0x04}   // payload
        );


    // valid tcp packet
    tests.push_back({valid_packet, ValidationError::NONE});

    // missing tcp header
    std::vector<uint8_t> missing_header = valid_packet;
    size_t ethernet_header_len = 14;
    uint8_t ihl = valid_packet[14] & 0x0F; // tcp header length is stored in low nibble of version_ihl byte
    size_t ip_header_len = ihl * 4;
    size_t tcp_offset  = ethernet_header_len + ip_header_len;
    missing_header.resize(tcp_offset);
    fix_ipv4_total_length(missing_header);
    fix_ipv4_checksum(missing_header);
    tests.push_back({missing_header, ValidationError::MISSING_TCP_HEADER});

    // too small for tcp
    std::vector<uint8_t> too_small = valid_packet;
    too_small.resize(tcp_offset + 10); // 10 since minimum tcp header length is 20 bytes;
    fix_ipv4_total_length(too_small);
    fix_ipv4_checksum(too_small);
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_TCP});

    // invalid tcp data offset (should ideally be  >= 5)
    std::vector<uint8_t> invalid_offset = valid_packet;
    invalid_offset[tcp_offset + 12] = (4 << 4); // (4 words or 16 bytes)
    tests.push_back({invalid_offset, ValidationError::INVALID_TCP_DATA_OFFSET});

    // tcp header exceeds packet
    std::vector<uint8_t> header_exceeds = valid_packet;
    header_exceeds[tcp_offset + 12] = (15 << 4); // 60 bytes header
    header_exceeds.resize(tcp_offset + 35); // 35 bytes actual (too short)
    fix_ipv4_total_length(header_exceeds);
    fix_ipv4_checksum(header_exceeds);
    tests.push_back({header_exceeds, ValidationError::TCP_HEADER_EXCEEDS_PACKET});

    // tcp invalid checksum
    std::vector<uint8_t> invalid_checksum = valid_packet;
    invalid_checksum[tcp_offset + 16] ^= 0xFF; // corrupt checksum high byte
    tests.push_back({invalid_checksum, ValidationError::TCP_INVALID_CHECKSUM});


    oss << "\n==== TCP TESTS ====\n" << std::endl;
    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";

    for (size_t i = 0; i < tests.size(); i++)    {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }
    oss << "\n=======================\n" << std::endl;
    std::cout << oss.str();
}



void run_udp_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid UDP packet using PacketBuilder
    uint8_t src_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    uint8_t src_ip[4] = {192,168,0,1};
    uint8_t dst_ip[4] = {192,168,0,2};

    std::vector<uint8_t> valid_packet =
        PacketBuilder::build_udp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            80,                     // src port
            443,                    // dest port
            {0x01,0x02,0x03,0x04}   // payload
        );


    // valid udp packet
    tests.push_back({valid_packet, ValidationError::NONE});

    // missing udp header
    std::vector<uint8_t> missing_header = valid_packet;
    size_t ethernet_header_len = 14;
    uint8_t ihl = valid_packet[14] & 0x0F; // udp header length is stored in low nibble of version_ihl byte
    size_t ip_header_len = ihl * 4;
    size_t udp_offset  = ethernet_header_len + ip_header_len;
    missing_header.resize(udp_offset);
    fix_ipv4_total_length(missing_header);
    fix_ipv4_checksum(missing_header);
    tests.push_back({missing_header, ValidationError::MISSING_UDP_HEADER});

    // too small for udp
    std::vector<uint8_t> too_small = valid_packet;
    too_small.resize(udp_offset + 4); // since udp header size is 8 bytes
    fix_ipv4_total_length(too_small);
    fix_ipv4_checksum(too_small);
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_UDP});
    
    // invalid udp length ( < 8)
    std::vector<uint8_t> invalid_length = valid_packet;
    invalid_length[udp_offset + 4] = 0x00;
    invalid_length[udp_offset + 5] = 0x06;
    fix_ipv4_total_length(invalid_length);
    fix_ipv4_checksum(invalid_length);
    tests.push_back({invalid_length, ValidationError::INVALID_UDP_LENGTH});

    // udp length exceeds packet
    std::vector<uint8_t> exceeds_packet = valid_packet;
    exceeds_packet[udp_offset + 4] = 0xFF;
    exceeds_packet[udp_offset + 5] = 0xFF;
    fix_ipv4_total_length(exceeds_packet);
    fix_ipv4_checksum(exceeds_packet);
    tests.push_back({exceeds_packet, ValidationError::UDP_LENGTH_EXCEEDS_PACKET});

    // udp invalid checksum
    std::vector<uint8_t> invalid_checksum = valid_packet;
    invalid_checksum[udp_offset + 6] ^= 0xFF; // corrupt checksum high byte
    tests.push_back({invalid_checksum, ValidationError::UDP_INVALID_CHECKSUM});


    oss << "\n==== UDP TESTS ====\n" << std::endl;
    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";

    for (size_t i = 0; i < tests.size(); i++)    {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }
    oss << "\n=======================\n" << std::endl;
    std::cout << oss.str();
}



void run_icmp_tests() {
    std::vector<std::pair<std::vector<uint8_t>, ValidationError>> tests;
    std::ostringstream oss;

    // Build valid ICMP Echo Request using PacketBuilder
    uint8_t src_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t dst_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    uint8_t src_ip[4] = {192,168,0,1};
    uint8_t dst_ip[4] = {192,168,0,2};

    std::vector<uint8_t> payload = {0xDE,0xAD,0xBE,0xEF};

    std::vector<uint8_t> valid_packet =
        PacketBuilder::build_icmp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            8,      // Echo Request
            0,      // Code
            0x1234, // Identifier
            0x0001, // Sequence
            payload
        );

    // valid icmp packet
    tests.push_back({valid_packet, ValidationError::NONE});

    // Compute offsets
    size_t ethernet_header_len = 14;
    uint8_t ihl = valid_packet[14] & 0x0F;
    size_t ip_header_len = ihl * 4;
    size_t icmp_offset = ethernet_header_len + ip_header_len;
    size_t icmp_header_len = 8;   // ICMP fixed header is always 8 bytes

    // missing icmp header
    std::vector<uint8_t> missing_header = valid_packet;
    missing_header.resize(icmp_offset);
    fix_ipv4_total_length(missing_header);
    fix_ipv4_checksum(missing_header);
    tests.push_back({missing_header, ValidationError::MISSING_ICMP_HEADER});

    // too small for icmp
    std::vector<uint8_t> too_small = valid_packet;
    too_small.resize(icmp_offset + 4); // ICMP header size is 8 bytes
    fix_ipv4_total_length(too_small);
    fix_ipv4_checksum(too_small);
    tests.push_back({too_small, ValidationError::TOO_SMALL_FOR_ICMP});

    // invalid type
    std::vector<uint8_t> invalid_type = valid_packet;
    invalid_type[icmp_offset] = 99; 
    fix_ipv4_total_length(invalid_type);
    fix_ipv4_checksum(invalid_type);
    tests.push_back({invalid_type, ValidationError::ICMP_INVALID_TYPE});

    // invalid code
    std::vector<uint8_t> invalid_code = valid_packet;
    invalid_code[icmp_offset + 1] = 5; // invalid for echo
    fix_ipv4_total_length(invalid_code);
    fix_ipv4_checksum(invalid_code);
    tests.push_back({invalid_code, ValidationError::ICMP_INVALID_CODE});

    // invalid checksum
    std::vector<uint8_t> invalid_checksum = valid_packet;
    invalid_checksum[icmp_offset + 2] ^= 0xFF; // corrupt by flipping bits
    fix_ipv4_total_length(invalid_checksum);
    fix_ipv4_checksum(invalid_checksum);
    tests.push_back({invalid_checksum, ValidationError::ICMP_INVALID_CHECKSUM});

    // truncated payload
    std::vector<uint8_t> truncated_payload = valid_packet;
    truncated_payload[icmp_offset] = 3; // set type to dest unreachable
    truncated_payload.resize(icmp_offset + 12); // less than 28 bytes
    fix_ipv4_total_length(truncated_payload);
    fix_ipv4_checksum(truncated_payload);
    tests.push_back({truncated_payload, ValidationError::ICMP_TRUNCATED_PAYLOAD});

    // embedded ipv4 invalid
    std::vector<uint8_t> invalid_embed = valid_packet;
    invalid_embed[icmp_offset] = 3; //set type to dest unreachable    
    invalid_embed.resize(icmp_offset + icmp_header_len + 28); // Ensure payload is not truncated
    invalid_embed[icmp_offset + icmp_header_len] = 0x60; 
    fix_ipv4_total_length(invalid_embed);
    fix_ipv4_checksum(invalid_embed);
    tests.push_back({invalid_embed, ValidationError::ICMP_EMBEDDED_IPV4_INVALID});

    
    oss << "\n==== ICMP TESTS ====\n" << std::endl;
    // table header
    oss << std::left << std::setw(8)  << "Test#" << std::setw(40) << "Expected" << std::setw(40) << "Received" << "Result" << "\n";
    oss << std::string(8 + 40 + 40 + 6, '-') << "\n";

    for (size_t i = 0; i < tests.size(); i++) {
        run_single_test(oss, static_cast<int>(i + 1), tests[i].first, tests[i].second);
    }
    oss << "\n=======================\n" << std::endl;
    std::cout << oss.str();
}


void run_capture_test() {

}



int main() {

    run_ethernet_tests();
    run_arp_tests();
    run_ipv4_tests();
    run_tcp_tests();
    run_udp_tests();
    run_icmp_tests();

    /* RAW CAPTURE TEST
    int res = raw_capture_test();    
    if(res!= 0){
        return 1;
    }
    */
    return 0;
}


/*
// RAW CAPTURE TEST
int run_capture_test(){
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

        std::cout << "\n=== Packet " << captured  << " (" << bytes << " bytes) ===\n";

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

*/