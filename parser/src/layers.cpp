#include "layers.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>

// TCP FLAG OFFSETS
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80

// LAYER 2 -> Ethernet Layer

EthernetLayer::EthernetLayer(const uint8_t* packet) {
    eth = reinterpret_cast<const EthernetHeader*>(packet);        
}

void EthernetLayer::print() const {
    std::cout << "=== ETHERNET LAYER ===" << std::endl;
    std::cout << "Source MAC: " << print_mac(eth->src_mac) << std::endl;
    std::cout << "Destination MAC: " << print_mac(eth->dest_mac) << std::endl;
    std::cout << "EtherType: " << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << ntohs(eth->ether_type) << std::dec << std::endl;
    std::cout << "=======================" << std::endl;
}

size_t EthernetLayer::header_size() const {
    return sizeof(EthernetHeader);
}

std::string EthernetLayer::print_mac(const uint8_t *mac){
    std::ostringstream oss;
    for(int i =0; i < 6; i++) {
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)mac[i];
        if(i < 5){
            oss << ":";
        }
    }
    return oss.str();
}


// LAYER 3 -> IPv4 Layer
IPv4Layer::IPv4Layer(const uint8_t *packet) {
    iph = reinterpret_cast<const IPv4Header*>(packet);
}

void IPv4Layer::print() const {
    std::cout << "=== IPv4 Layer ===" << std::endl;
    std::cout << "Source IP: " << print_ip(iph->src_addr) << std::endl;
    std::cout << "Destination IP: " << print_ip(iph->dest_addr) << std::endl;
    std::cout << "Protocol: " << (int) iph->protocol << std::endl;
    std::cout << "==================" << std::endl;

}

size_t IPv4Layer::header_size() const {
    return (iph->version_ihl & 0x0F) * 4;
}

std::string IPv4Layer::print_ip(uint32_t ip){
    std::ostringstream oss;
    ip = ntohl(ip);
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
        return oss.str();
}

// LAYER 4 -> TCP Header
TCPLayer::TCPLayer(const uint8_t *packet){
    tcph = reinterpret_cast<const TCPHeader*>(packet);
}

void TCPLayer::print() const {
    std::cout << "=== TCP Layer ===" << std::endl;
    std::cout << "Source Port: " << ntohs(tcph->src_port) << std::endl;
    std::cout << "Destination Port: " << ntohs(tcph->dest_port) << std::endl;
    std::cout << "Flags: ";
    std::vector<std::string> flags = decode_tcp_flags(tcph->flags);
    for(size_t i = 0; i < flags.size(); i++){
        std::cout << flags[i];
        if(i < flags.size() - 1) {
            std::cout << " ";
        }
    }
    std::cout << std::endl;
    std::cout << "=================" << std::endl;
}

size_t TCPLayer::header_size() const {
    return ((tcph->data_offset >> 4) & 0x0F) * 4;
}

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


// LAYER 4 -> UDP Header
UDPLayer::UDPLayer(const uint8_t *packet) {
    udph = reinterpret_cast<const UDPHeader*>(packet);
}
void UDPLayer::print() const {
    std::cout << "=== UDP Layer ===" << std::endl;
    std::cout << "Source Port: " << ntohs(udph->src) << std::endl;
    std::cout << "Destination Port: " << ntohs(udph->dest) << std::endl;
    std::cout << "Length: " << ntohs(udph->length) << std::endl;
    std::cout << "Checksum: " << ntohs(udph->checksum) << std::endl;
    std::cout << "=================" << std::endl;
}

size_t UDPLayer::header_size() const {
    return sizeof(UDPHeader);
}

