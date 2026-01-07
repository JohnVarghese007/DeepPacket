#include <iostream>
#include "parser.hpp"

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


int main() {
    std::cout << "=== TCP PACKET ===" << std::endl;
    ParsedPacket tcp = parse_packet(std::span<const uint8_t>(sample_tcp_packet));
    tcp.view.print();

    std::cout << "=== UDP PACKET ===" << std::endl;
    ParsedPacket udp = parse_packet(std::span<const uint8_t>(sample_udp_packet));
    udp.view.print();

    return 0;
}
