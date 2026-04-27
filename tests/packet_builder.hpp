#pragma once
#include <vector>
#include <cstdint>
#include <cstring>


// --- Validator-matching checksum ---
inline uint16_t compute_checksum(const uint8_t* buffer, size_t len) {
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word = (buffer[0] << 8) | buffer[1];
        sum += word;
        buffer += 2;
        len -= 2;

        if (sum & 0x10000)
            sum = (sum & 0xFFFF) + 1;
    }

    if (len == 1) {
        sum += buffer[0] << 8;
        if (sum & 0x10000)
            sum = (sum & 0xFFFF) + 1;
    }

    return ~sum & 0xFFFF;
}

// --- Validator-matching TCP/UDP checksum ---
inline uint16_t transport_checksum_validator_style(
    const uint8_t* src_ip,
    const uint8_t* dst_ip,
    uint8_t protocol,
    const uint8_t* segment,
    size_t seg_len
) {
    // Build pseudo-header (12 bytes)
    uint8_t pseudo[12];
    memcpy(pseudo,     src_ip, 4);
    memcpy(pseudo + 4, dst_ip, 4);
    pseudo[8]  = 0;
    pseudo[9]  = protocol;
    pseudo[10] = (seg_len >> 8) & 0xFF;
    pseudo[11] = seg_len & 0xFF;

    // Copy segment into temp buffer so we can zero checksum field
    uint8_t temp[65535];
    memcpy(temp, segment, seg_len);

    // Zero checksum field (bytes 16–17 of TCP/UDP header)
    temp[16] = 0;
    temp[17] = 0;

    // Compute checksum exactly like validator
    uint32_t sum = compute_checksum(pseudo, 12);
    sum += compute_checksum(temp, seg_len);

    // Fold carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum & 0xFFFF;
}

class PacketBuilder {
public:

    static std::vector<uint8_t> build_ipv6_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],
        const uint8_t src_ip[16],
        const uint8_t dst_ip[16],
        uint8_t next_header,
        uint8_t hop_limit,
        const std::vector<uint8_t>& payload
    ) {
        std::vector<uint8_t> pkt;

        // -------------------------
        // Ethernet Header (14 bytes)
        // -------------------------
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x86); // EtherType = IPv6 (0x86DD)
        pkt.push_back(0xDD);

        // -------------------------
        // IPv6 Header (40 bytes)
        // -------------------------

        // Version=6, Traffic Class=0, Flow Label=0
        pkt.push_back(0x60);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // Payload length (16-bit)
        uint16_t payload_len = payload.size();
        pkt.push_back((payload_len >> 8) & 0xFF);
        pkt.push_back(payload_len & 0xFF);

        // Next Header (caller chooses)
        pkt.push_back(next_header);

        // Hop Limit
        pkt.push_back(hop_limit);

        // Source IPv6
        pkt.insert(pkt.end(), src_ip, src_ip + 16);

        // Destination IPv6
        pkt.insert(pkt.end(), dst_ip, dst_ip + 16);

        // -------------------------
        // Payload
        // -------------------------
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        return pkt;
    }

    static std::vector<uint8_t> build_tcp_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],
        const uint8_t src_ip[4],
        const uint8_t dst_ip[4],
        uint16_t src_port,
        uint16_t dst_port,
        const std::vector<uint8_t>& payload
    ) {
        std::vector<uint8_t> pkt;

        // Ethernet header
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x08); pkt.push_back(0x00);

        // IPv4 header
        size_t ip_header_start = pkt.size();
        pkt.push_back(0x45);
        pkt.push_back(0x00);

        uint16_t total_len = 20 + 20 + payload.size();
        pkt.push_back(total_len >> 8);
        pkt.push_back(total_len & 0xFF);

        pkt.push_back(0x00); pkt.push_back(0x01);
        pkt.push_back(0x00); pkt.push_back(0x00);
        pkt.push_back(64);
        pkt.push_back(6);

        pkt.push_back(0x00); pkt.push_back(0x00);

        pkt.insert(pkt.end(), src_ip, src_ip + 4);
        pkt.insert(pkt.end(), dst_ip, dst_ip + 4);

        // TCP header
        size_t tcp_start = pkt.size();

        pkt.push_back(src_port >> 8); pkt.push_back(src_port & 0xFF);
        pkt.push_back(dst_port >> 8); pkt.push_back(dst_port & 0xFF);

        for (int i = 0; i < 8; i++) pkt.push_back(0x00);

        pkt.push_back(0x50);
        pkt.push_back(0x02);
        pkt.push_back(0x20); pkt.push_back(0x00);

        pkt.push_back(0x00); pkt.push_back(0x00);
        pkt.push_back(0x00); pkt.push_back(0x00);

        pkt.insert(pkt.end(), payload.begin(), payload.end());

        // Compute TCP checksum 
        uint16_t tcp_len = 20 + payload.size();
        uint16_t csum = transport_checksum_validator_style(
            src_ip, dst_ip, 6,
            &pkt[tcp_start], tcp_len
        );

        pkt[tcp_start + 16] = csum >> 8;
        pkt[tcp_start + 17] = csum & 0xFF;

        // IPv4 checksum
        uint16_t ip_csum = compute_checksum(&pkt[ip_header_start], 20);
        pkt[ip_header_start + 10] = ip_csum >> 8;
        pkt[ip_header_start + 11] = ip_csum & 0xFF;

        return pkt;
    }

    static std::vector<uint8_t> build_udp_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],
        const uint8_t src_ip[4],
        const uint8_t dst_ip[4],
        uint16_t src_port,
        uint16_t dst_port,
        const std::vector<uint8_t>& payload
    ) {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x08); pkt.push_back(0x00);

        // IPv4
        size_t ip_header_start = pkt.size();
        pkt.push_back(0x45);
        pkt.push_back(0x00);

        uint16_t total_len = 20 + 8 + payload.size();
        pkt.push_back(total_len >> 8);
        pkt.push_back(total_len & 0xFF);

        pkt.push_back(0x00); pkt.push_back(0x02);
        pkt.push_back(0x00); pkt.push_back(0x00);
        pkt.push_back(64);
        pkt.push_back(17);

        pkt.push_back(0x00); pkt.push_back(0x00);

        pkt.insert(pkt.end(), src_ip, src_ip + 4);
        pkt.insert(pkt.end(), dst_ip, dst_ip + 4);

        // UDP
        size_t udp_start = pkt.size();

        pkt.push_back(src_port >> 8); pkt.push_back(src_port & 0xFF);
        pkt.push_back(dst_port >> 8); pkt.push_back(dst_port & 0xFF);

        uint16_t udp_len = 8 + payload.size();
        pkt.push_back(udp_len >> 8);
        pkt.push_back(udp_len & 0xFF);

        pkt.push_back(0x00); pkt.push_back(0x00);

        pkt.insert(pkt.end(), payload.begin(), payload.end());

        // UDP checksum (validator-style)
        uint16_t csum = transport_checksum_validator_style(
            src_ip, dst_ip, 17,
            &pkt[udp_start], udp_len
        );

        pkt[udp_start + 6] = csum >> 8;
        pkt[udp_start + 7] = csum & 0xFF;

        // IPv4 checksum
        uint16_t ip_csum = compute_checksum(&pkt[ip_header_start], 20);
        pkt[ip_header_start + 10] = ip_csum >> 8;
        pkt[ip_header_start + 11] = ip_csum & 0xFF;

        return pkt;
    }
    

    static std::vector<uint8_t> build_arp_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],      // Usually broadcast FF:FF:FF:FF:FF:FF for ARP request
        const uint8_t sender_mac[6],
        const uint8_t sender_ip[4],
        const uint8_t target_mac[6],   // Zero for ARP request
        const uint8_t target_ip[4],
        uint16_t opcode                // 1 = request, 2 = reply
    ) {
        std::vector<uint8_t> pkt;

        // -------------------------
        // Ethernet Header
        // -------------------------
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x08); pkt.push_back(0x06); // Ethertype = ARP

        // -------------------------
        // ARP Header
        // -------------------------

        // Hardware type = Ethernet (1)
        pkt.push_back(0x00); pkt.push_back(0x01);

        // Protocol type = IPv4 (0x0800)
        pkt.push_back(0x08); pkt.push_back(0x00);

        // Hardware size = 6, Protocol size = 4
        pkt.push_back(6);
        pkt.push_back(4);

        // Opcode (1=request, 2=reply)
        pkt.push_back(opcode >> 8);
        pkt.push_back(opcode & 0xFF);

        // Sender MAC
        pkt.insert(pkt.end(), sender_mac, sender_mac + 6);

        // Sender IP
        pkt.insert(pkt.end(), sender_ip, sender_ip + 4);

        // Target MAC
        pkt.insert(pkt.end(), target_mac, target_mac + 6);

        // Target IP
        pkt.insert(pkt.end(), target_ip, target_ip + 4);

        return pkt;
    }


    static std::vector<uint8_t> build_icmpv4_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],
        const uint8_t src_ip[4],
        const uint8_t dst_ip[4],
        uint8_t icmp_type,     // 8 = echo request, 0 = echo reply
        uint8_t icmp_code,     // usually 0
        uint16_t identifier,
        uint16_t sequence,
        const std::vector<uint8_t>& payload
    ) {
        std::vector<uint8_t> pkt;

        // -------------------------
        // Ethernet Header
        // -------------------------
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x08); pkt.push_back(0x00); // IPv4

        // -------------------------
        // IPv4 Header
        // -------------------------
        size_t ip_header_start = pkt.size();

        pkt.push_back(0x45); // Version=4, IHL=5
        pkt.push_back(0x00); // DSCP/ECN

        uint16_t total_len = 20 + 8 + payload.size(); // IPv4 + ICMP header + payload
        pkt.push_back(total_len >> 8);
        pkt.push_back(total_len & 0xFF);

        pkt.push_back(0x00); pkt.push_back(0x03); // ID
        pkt.push_back(0x00); pkt.push_back(0x00); // Flags/Frag
        pkt.push_back(64);                       // TTL
        pkt.push_back(1);                        // Protocol = ICMP

        pkt.push_back(0x00); pkt.push_back(0x00); // checksum placeholder

        pkt.insert(pkt.end(), src_ip, src_ip + 4);
        pkt.insert(pkt.end(), dst_ip, dst_ip + 4);

        // -------------------------
        // ICMP Header
        // -------------------------
        size_t icmp_start = pkt.size();

        pkt.push_back(icmp_type);
        pkt.push_back(icmp_code);

        pkt.push_back(0x00); pkt.push_back(0x00); // checksum placeholder

        pkt.push_back(identifier >> 8);
        pkt.push_back(identifier & 0xFF);

        pkt.push_back(sequence >> 8);
        pkt.push_back(sequence & 0xFF);

        // Payload
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        // -------------------------
        // Compute ICMP checksum
        // -------------------------
        uint16_t icmp_len = 8 + payload.size();

        // Copy ICMP segment into temp buffer
        uint8_t temp[65535];
        memcpy(temp, &pkt[icmp_start], icmp_len);

        // Zero checksum field
        temp[2] = 0;
        temp[3] = 0;

        uint16_t icmp_csum = compute_checksum(temp, icmp_len);

        pkt[icmp_start + 2] = icmp_csum >> 8;
        pkt[icmp_start + 3] = icmp_csum & 0xFF;

        // -------------------------
        // Compute IPv4 checksum
        // -------------------------
        uint16_t ip_csum = compute_checksum(&pkt[ip_header_start], 20);
        pkt[ip_header_start + 10] = ip_csum >> 8;
        pkt[ip_header_start + 11] = ip_csum & 0xFF;

        return pkt;
    }


    static std::vector<uint8_t> build_icmpv6_packet(
        const uint8_t src_mac[6],
        const uint8_t dst_mac[6],
        const uint8_t src_ip[16],
        const uint8_t dst_ip[16],
        uint8_t type,   //  128 = echo request, 129 = echo reply
        uint8_t code,         
        uint16_t identifier,
        uint16_t sequence,
        const std::vector<uint8_t>& payload
    ) {
        std::vector<uint8_t> pkt;

        // -------------------------
        // Ethernet Header (14 bytes)
        // -------------------------
        pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
        pkt.insert(pkt.end(), src_mac, src_mac + 6);
        pkt.push_back(0x86); // EtherType = IPv6 (0x86DD)
        pkt.push_back(0xDD);

        // -------------------------
        // IPv6 Header (40 bytes)
        // -------------------------

        // Version=6, Traffic Class=0, Flow Label=0
        pkt.push_back(0x60);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // Payload length = ICMPv6 header (8) + payload
        uint16_t payload_len = 8 + payload.size();
        pkt.push_back((payload_len >> 8) & 0xFF);
        pkt.push_back(payload_len & 0xFF);

        // Next Header = 58 (ICMPv6)
        pkt.push_back(58);

        // Hop Limit
        pkt.push_back(64);

        // Source IPv6
        pkt.insert(pkt.end(), src_ip, src_ip + 16);

        // Destination IPv6
        pkt.insert(pkt.end(), dst_ip, dst_ip + 16);

        // -------------------------
        // ICMPv6 Header (8 bytes)
        // -------------------------
        size_t icmp_start = pkt.size();

        pkt.push_back(type);
        pkt.push_back(code);

        // Checksum placeholder
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // Identifier
        pkt.push_back((identifier >> 8) & 0xFF);
        pkt.push_back(identifier & 0xFF);

        // Sequence
        pkt.push_back((sequence >> 8) & 0xFF);
        pkt.push_back(sequence & 0xFF);

        // Payload
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        // -------------------------
        // Compute ICMPv6 checksum
        // -------------------------

        // Build pseudo-header
        std::vector<uint8_t> pseudo;
        pseudo.insert(pseudo.end(), src_ip, src_ip + 16);
        pseudo.insert(pseudo.end(), dst_ip, dst_ip + 16);

        uint32_t upper_len = payload_len;
        pseudo.push_back((upper_len >> 24) & 0xFF);
        pseudo.push_back((upper_len >> 16) & 0xFF);
        pseudo.push_back((upper_len >> 8) & 0xFF);
        pseudo.push_back(upper_len & 0xFF);

        pseudo.push_back(0x00);
        pseudo.push_back(0x00);
        pseudo.push_back(0x00);
        pseudo.push_back(58); // Next Header = ICMPv6

        // Copy ICMPv6 segment
        std::vector<uint8_t> icmp_segment(pkt.begin() + icmp_start, pkt.end());

        // Zero checksum field
        icmp_segment[2] = 0;
        icmp_segment[3] = 0;

        // Compute checksum
        uint32_t sum = compute_checksum(pseudo.data(), pseudo.size());
        sum += compute_checksum(icmp_segment.data(), icmp_segment.size());

        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        uint16_t checksum = ~sum & 0xFFFF;

        // Write checksum back
        pkt[icmp_start + 2] = (checksum >> 8) & 0xFF;
        pkt[icmp_start + 3] = checksum & 0xFF;

        return pkt;
    }

};