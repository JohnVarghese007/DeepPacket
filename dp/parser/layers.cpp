#include "dp/parser/layers.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>


namespace dp::parser::layers {

// TCP FLAG OFFSETS
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80

/*
    Network Layers Implementation
    - This file contains implementations of the following classes:
        - EthernetLayer
        - ARPLayer
        - IPv4Layer
        - TCPLayer
        - UDPLayer
        - ICMPv4Layer
        - ICMPv6Layer
*/



// LAYER 2 -> Ethernet Layer
EthernetLayer::EthernetLayer(const uint8_t* packet) {
    eth = reinterpret_cast<const EthernetHeader*>(packet);        
}

void EthernetLayer::print(std::ostream& os) const {
    os << "=== ETHERNET LAYER ===" << std::endl;
    os << "Source MAC: ";
    print_mac(eth->src_mac, os);
    os << std::endl;
    os << "Destination MAC: ";
    print_mac(eth->dest_mac, os);
    os << std::endl;
    os << "EtherType: " << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << ntohs(eth->ether_type) << std::dec << std::endl;
    os << "=======================" << std::endl;
}

size_t EthernetLayer::header_size() const {
    return sizeof(EthernetHeader);
}

void EthernetLayer::print_mac(const uint8_t *mac, std::ostream& os){
    for(int i =0; i < 6; i++) {
        os << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)mac[i];
        if(i < 5){
            os << ":";
        }
    }
}


// LAYER 2.5 -> ARP Layer
ARPLayer::ARPLayer(const uint8_t *packet) {
    arp = reinterpret_cast<const ARPHeader*>(packet);
}

void ARPLayer::print(std::ostream& os) const {
    os << "=== ARP LAYER ===" << std::endl;
    // opcode -> 1= Request, 2 = Reply
    uint16_t opcode = ntohs(arp->opcode);
    os << "Opcode: " << opcode;
    if(opcode == 1) os << "(Request)";
    else if(opcode == 2) os << "(Reply)";
    else os << "(Invalid)";
    os << std::endl;

    // Copy IPs to 32 bit
    uint32_t sender_ip_raw;
    std::memcpy(&sender_ip_raw, arp->sender_ip, 4);
    uint32_t target_ip_raw;
    std::memcpy(&target_ip_raw, arp->target_ip, 4);

    os << "Sender MAC: ";
    print_mac(arp->sender_mac, os);
    os << std::endl;
    os << "Sender IP: ";
    print_ip(sender_ip_raw, os);
    os << std::endl;
    os << "Target MAC: ";
    print_mac(arp->target_mac, os);
    os << std::endl;
    os << "Target IP: ";
    print_ip(target_ip_raw, os);
    os << std::endl;
    os << "=======================" << std::endl;
}

size_t ARPLayer::header_size() const {
    return sizeof(ARPHeader);
}

void ARPLayer::print_mac(const uint8_t *mac, std::ostream& os){
    for(int i =0; i < 6; i++) {
        os << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)mac[i];
        if(i < 5){
            os << ":";
        }
    }
}

void ARPLayer::print_ip(uint32_t ip, std::ostream& os){
    ip = ntohl(ip);
    os << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
}



// LAYER 3 -> IPv4 Layer
IPv4Layer::IPv4Layer(const uint8_t *packet) {
    iph = reinterpret_cast<const IPv4Header*>(packet);
}

void IPv4Layer::print(std::ostream& os) const {
    os << "=== IPv4 Layer ===" << std::endl;
    os << "Source IP: ";
    print_ipv4(iph->src_addr, os);
    os << std::endl;
    os << "Destination IP: ";
    print_ipv4(iph->dest_addr, os);
    os << std::endl;
    os << "Protocol: " << (int) iph->protocol << std::endl;
    os << "==================" << std::endl;

}

size_t IPv4Layer::header_size() const {
    return (iph->version_ihl & 0x0F) * 4;
}

void IPv4Layer::print_ipv4(uint32_t ip, std::ostream& os){
    ip = ntohl(ip);
    os << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
}



// LAYER 3 -> IPv6 Layer
IPv6Layer::IPv6Layer(const uint8_t *packet) {
    iph = reinterpret_cast<const IPv6Header*>(packet);
}

void IPv6Layer::print(std::ostream& os) const {
    os << "=== IPv6 Layer ===" << std::endl;
    os << "Source IP: ";
    print_ipv6(iph->src_addr, os);
    os << std::endl;
    os << "Destination IP: ";
    print_ipv6(iph->dest_addr, os);
    os << std::endl;
    os << "Next Header: " << (int) iph->next_header << std::endl;
    os << "Hop Limit: " << (int) iph->hop_limit << std::endl;
    os << "==================" << std::endl;
}

size_t IPv6Layer::header_size() const {
    return sizeof(IPv6Header);
}

void IPv6Layer::print_ipv6(uint8_t addr[16], std::ostream& os) {
    char buf[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)) != nullptr) {
        os << buf;
    } else {
        os << "<invalid IPv6>";
    }
}



// LAYER 4 -> TCP Layer
TCPLayer::TCPLayer(const uint8_t *packet){
    tcph = reinterpret_cast<const TCPHeader*>(packet);
}

void TCPLayer::print(std::ostream& os) const {
    os << "=== TCP Layer ===" << std::endl;
    os << "Source Port: " << ntohs(tcph->src_port) << std::endl;
    os << "Destination Port: " << ntohs(tcph->dest_port) << std::endl;
    os << "Flags: ";
    std::vector<std::string> flags = decode_tcp_flags(tcph->flags);
    for(size_t i = 0; i < flags.size(); i++){
        os << flags[i];
        if(i < flags.size() - 1) {
            os << " ";
        }
    }
    os << std::endl;
    os << "=================" << std::endl;
}

size_t TCPLayer::header_size() const {
    return ((tcph->data_offset >> 4) & 0x0F) * 4;
}

// Decodes TCP flag field
std::vector<std::string> TCPLayer::decode_tcp_flags(uint8_t flags) {

    std::vector<std::string> result;

    bool fin = flags & FIN_FLAG;
    bool syn = flags & SYN_FLAG;
    bool rst = flags & RST_FLAG;
    bool psh = flags & PSH_FLAG;
    bool ack = flags & ACK_FLAG;
    bool urg = flags & URG_FLAG;
    bool ece = flags & ECE_FLAG;
    bool cwr = flags & CWR_FLAG;

    if(fin) result.push_back("FIN");
    if(syn) result.push_back("SYN");
    if(rst) result.push_back("RST");
    if(psh) result.push_back("PSH");
    if(ack) result.push_back("ACK");
    if(urg) result.push_back("URG");
    if(ece) result.push_back("ECE");
    if(cwr) result.push_back("CWR");

    return result;
}



// LAYER 4 -> UDP Layer
UDPLayer::UDPLayer(const uint8_t *packet) {
    udph = reinterpret_cast<const UDPHeader*>(packet);
}

void UDPLayer::print(std::ostream& os) const {
    os << "=== UDP Layer ===" << std::endl;
    os << "Source Port: " << ntohs(udph->src) << std::endl;
    os << "Destination Port: " << ntohs(udph->dest) << std::endl;
    os << "Length: " << ntohs(udph->length) << std::endl;
    os << "Checksum: " << ntohs(udph->checksum) << std::endl;
    os << "=================" << std::endl;
}

size_t UDPLayer::header_size() const {
    return sizeof(UDPHeader);
}



// NETWORK CONTROL (Layer 3) -> ICMPv4 Layer
// ICMPv4 is a network-layer control protocol carried inside IPv4.
ICMPv4Layer::ICMPv4Layer(const uint8_t *packet) { 
    icmph = reinterpret_cast<const ICMPv4Header*>(packet);
    echo = nullptr;
    unreach = nullptr;
    redirect = nullptr;
    param = nullptr;

    size_t fixed_offset = sizeof(ICMPv4Header);
    switch(icmph ->type) {

        case 0: // reply
        case 8: // request
            echo = reinterpret_cast<const ICMPv4Echo*>(packet + fixed_offset);
            break;

        case 3:
            unreach = reinterpret_cast<const ICMPv4DestUnreach*>(packet + fixed_offset);
            break;
            
        case 5:
            redirect = reinterpret_cast<const ICMPv4Redirect*>(packet + fixed_offset);
            break;

        case 12:
            param = reinterpret_cast<const ICMPv4ParamProblem*>(packet + fixed_offset);
            break;

        default:
            // unsupported type
            break;

    }
}

void ICMPv4Layer::print(std::ostream& os) const {
    os << "=== ICMPv4 Layer ===" << std::endl;
    os << "Type: " << icmph->type << std::endl;
    os << "Code: " << icmph->code << std::endl;
    os << "Checksum: " << ntohs(icmph->checksum) << std::endl;
    os << "=================" << std::endl;
}

size_t ICMPv4Layer::header_size() const {
    size_t res = sizeof(ICMPv4Header);

    if(echo) res += sizeof(ICMPv4Echo);
    if(unreach) res += sizeof(ICMPv4DestUnreach);
    if(redirect) res += sizeof(ICMPv4Redirect);
    if(param) res+= sizeof(ICMPv4ParamProblem);

    return res;
}




// NETWORK CONTROL (Layer 3) -> ICMPv6 Layer
// ICMPv6 is a network-layer control protocol carried inside IPv6.
ICMPv6Layer::ICMPv6Layer(const uint8_t *packet) { 
    icmph = reinterpret_cast<const ICMPv6Header*>(packet);
    echo = nullptr;
    error = nullptr;

    size_t fixed_offset = sizeof(ICMPv6Header);
    switch(icmph ->type) {

        // errors
        case 1:
        case 2:
        case 3:
        case 4:
            error = reinterpret_cast<const ICMPv6Error*>(packet + fixed_offset);    
            break;

        // echo
        case 128:
        case 129:
            echo = reinterpret_cast<const ICMPv6Echo*>(packet + fixed_offset);
            break;
            
        default:
            // unsupported type
            break;

    }
}

void ICMPv6Layer::print(std::ostream& os) const {
    os << "=== ICMPv6 Layer ===" << std::endl;
    os << "Type: " << icmph->type << std::endl;
    os << "Code: " << icmph->code << std::endl;
    os << "Checksum: " << ntohs(icmph->checksum) << std::endl;
    os << "=================" << std::endl;
}

size_t ICMPv6Layer::header_size() const {
    size_t res = sizeof(ICMPv6Header);    
    if(echo) res += sizeof(ICMPv6Echo);
    if(error) res += sizeof(ICMPv6Error);
    return res;
}

} // namespace dp::parser::layers

