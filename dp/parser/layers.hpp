#pragma once

#include "dp/parser/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <ostream>


namespace dp {
namespace parser {
namespace layers {

// LAYER 2 -> Ethernet Layer
class EthernetLayer {
public: 
    const EthernetHeader *eth;

    EthernetLayer() : eth(nullptr) {}
    EthernetLayer(const uint8_t* packet); 

    void print(std::ostream& os) const;
    size_t header_size() const;

private:
    static void print_mac(const uint8_t *mac, std::ostream& os);
};


// LAYER 2.5 -> ARP Layer
class ARPLayer {
public:
    const ARPHeader *arp;

    ARPLayer() : arp(nullptr) {}
    ARPLayer(const uint8_t* packet);

    void print(std::ostream& os) const;
    size_t header_size() const;

private:
    static void print_mac(const uint8_t *mac, std::ostream& os);
    static void print_ip(const uint32_t ip, std::ostream& os);
};


// LAYER 3 -> IPv4 Layer
class IPv4Layer {
public:
    const IPv4Header *iph;

    IPv4Layer() : iph(nullptr) {}
    IPv4Layer(const uint8_t *packet);

    void print(std::ostream& os) const;
    size_t header_size() const;

private:
    static void print_ipv4(uint32_t ip, std::ostream& os);
};


// LAYER 3 -> IPv6 Layer
class IPv6Layer {
public:
    const IPv6Header *iph;

    IPv6Layer() : iph(nullptr) {}
    IPv6Layer(const uint8_t *packet);

    void print(std::ostream& os) const;
    size_t header_size() const;

private:
    static void print_ipv6(uint8_t addr[16], std::ostream& os);
};


// Layer 4 -> TCP Layer
class TCPLayer {
public:
    const TCPHeader *tcph;

    TCPLayer() : tcph(nullptr) {}
    TCPLayer(const uint8_t *packet);

    void print(std::ostream& os) const;
    size_t header_size() const;

private:
    static std::vector<std::string> decode_tcp_flags(uint8_t flags);
};


// LAYER 4 -> UDP Layer
class UDPLayer {
public:
    const UDPHeader *udph;

    UDPLayer() : udph(nullptr) {}
    UDPLayer(const uint8_t *packet);

    void print(std::ostream& os) const;
    size_t header_size() const;

};


// NETWORK CONTROL -> ICMPv4 Layer (carried inside IPv4)
class ICMPv4Layer {
public:
    const ICMPv4Header *icmph;
    const ICMPv4Echo *echo;
    const ICMPv4DestUnreach *unreach;
    const ICMPv4Redirect *redirect;
    const ICMPv4ParamProblem *param;

    ICMPv4Layer() : icmph(nullptr), echo(nullptr), unreach(nullptr), redirect(nullptr), param(nullptr) {}
    ICMPv4Layer(const uint8_t *packet);
    
    void print(std::ostream& os) const;
    size_t header_size() const;

};


// NETWORK CONTROL -> ICMPv6 Layer (carried inside IPv6)
class ICMPv6Layer {
public:
    const ICMPv6Header *icmph;
    const ICMPv6Echo *echo;
    const ICMPv6Error *error;

    ICMPv6Layer() : icmph(nullptr), echo(nullptr), error(nullptr) {}
    ICMPv6Layer(const uint8_t *packet);

     void print(std::ostream& os) const;
    size_t header_size() const;
};


} // namespace layers
} // namespace parser
} // namespace dp

