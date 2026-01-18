#pragma once

#include "packet.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>


// LAYER 2 -> Ethernet Layer
class EthernetLayer {
public: 
    const EthernetHeader *eth;

    EthernetLayer() : eth(nullptr) {}
    EthernetLayer(const uint8_t* packet); 

    void print() const;
    size_t header_size() const;

private:
    static std::string print_mac(const uint8_t *mac);
};


// LAYER 2.5 -> ARP Layer
class ARPLayer {
public:
    const ARPHeader *arp;

    ARPLayer() : arp(nullptr) {}
    ARPLayer(const uint8_t* packet);

    void print() const;
    size_t header_size() const;

private:
    static std::string print_mac(const uint8_t *mac);
    static std::string print_ip(const uint32_t ip);
};


// LAYER 3 -> IPv4 Layer
class IPv4Layer {
public:
    const IPv4Header *iph;

    IPv4Layer() : iph(nullptr) {}
    IPv4Layer(const uint8_t *packet);

    void print() const;
    size_t header_size() const;

private:
    static std::string print_ip(uint32_t ip);
};


// Layer 4 -> TCP Header
class TCPLayer {
public:
    const TCPHeader *tcph;

    TCPLayer() : tcph(nullptr) {}
    TCPLayer(const uint8_t *packet);

    void print() const;
    size_t header_size() const;

private:
    static std::vector<std::string> decode_tcp_flags(uint8_t flags);
};


// LAYER 4 -> UDP Header
class UDPLayer {
public:
    const UDPHeader *udph;

    UDPLayer() : udph(nullptr) {}
    UDPLayer(const uint8_t *packet);

    void print() const;
    size_t header_size() const;

};


