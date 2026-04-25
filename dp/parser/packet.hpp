#pragma once
#include <cstdint>


namespace dp {
namespace parser {


/*
    NOTE 
    ----
    This file uses OSI-style naming for clarity:

      - Layer 2  : Ethernet (Data Link)
      - Layer 2.5: ARP (Link/Network boundary)
      - Layer 3  : IPv4 / IPv6 (Network Layer)
      - Layer 4  : TCP / UDP (Transport Layer)

    ICMPv4 and ICMPv6 are not Transport-layer protocols.
    They are Network-layer control protocols carried inside IP.
    However, they appear as "next protocol" after IPv4/IPv6,
    so they are grouped with Transport-layer parsing in PacketView.

*/


#pragma pack(push, 1)

// LAYER 2 -> Ethernet Header
struct EthernetHeader {
    uint8_t dest_mac[6];  
    uint8_t src_mac[6];   
    uint16_t ether_type;  // (0x0800, 0x86DD etc.)
};


// ARP header (technically both layers 2 and 3)
struct ARPHeader {
    uint16_t hardware_type;       // Hardware type (1 -> Ethernet)
    uint16_t protocol_type;     // (0x0800, 0x0806 etc.)
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;            // Request -> 1, Reply -> 2
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];

};


// LAYER 3 -> IPv4 Header
struct IPv4Header {
    uint8_t  version_ihl;      // Version (4 bits) + IHL (4 bits)
    uint8_t  dscp_ecn;         // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;     // Total length of packet (header + payload)
    uint16_t identification;   // Unique ID for fragmentation
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;              // Time To Live
    uint8_t  protocol;         // L4 Protocol number (TCP=6, UDP=17, ICMP=1)
    uint16_t header_checksum;  
    uint32_t src_addr;         // Source IP address
    uint32_t dest_addr;         // Destination IP address
};


// LAYER 3 -> IPv6 Header
struct IPv6Header {
    uint32_t ver_tc_fl;     // Version (4) + Traffic Class (8) + Flow Label (20)
    uint16_t payload_length;
    uint8_t  next_header;   // L4 protocol or extension header
    uint8_t  hop_limit;
    uint8_t  src_addr[16];
    uint8_t  dest_addr[16];
};


// LAYER 4 -> TCP Header
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags; 
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentptr;
};

// LAYER 4 -> UDP Header
struct UDPHeader {
    uint16_t src;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
};

// LAYER 4 -> ICMPv4 fixed header
struct ICMPv4Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

// ICMPv4 variable headers depending on type
// type 0 or 8
struct ICMPv4Echo {
    uint16_t identifier;
    uint16_t sequence;
};

// type 3
struct ICMPv4DestUnreach {
    uint32_t data; // unused or mtu depending on code
};

// type 5
struct ICMPv4Redirect {
    uint32_t gateway_ip;
};

// type 12
struct ICMPv4ParamProblem {
    uint8_t pointer;
    uint8_t unused[3];
};

// Network Layer Control Protocol -> ICMPv6 fixed header
struct ICMPv6Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

// ICMPv6 variable headers depending on type
// types 1, 2, 3, 4
struct ICMPv6Error {
    uint32_t data; // unused or mtu depending on type/code
};

// type 128 or 129
struct ICMPv6Echo {
    uint16_t identifier;
    uint16_t sequence;
};

#pragma pack(pop)


// Supported IP Protocols
enum class IpProto {
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
    UNKNOWN
};

} // namespace parser
} // namespace dp