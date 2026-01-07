#pragma once

#include "packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>


// LAYER 2 -> Ethernet Layer
class EthernetLayer {
public: 
    const EthernetHeader *eth;

    // Default Constructor
    EthernetLayer() : eth(nullptr) {}

    // EthernetLayer Constructor
    EthernetLayer(const uint8_t* packet); 

    void print() const;
    size_t header_size() const;

private:
    static std::string print_mac(const uint8_t *mac);
};



// LAYER 3 -> IPv4 Layer
class IPv4Layer {
public:
    const IPv4Header *iph;

    // Default Constructor
    IPv4Layer() : iph(nullptr) {}
    // IPv4Layer Constructor
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

    // Default Constructor
    TCPLayer() : tcph(nullptr) {}

    // TCPLayer Constructor
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

    // Default Constructor
    UDPLayer() : udph(nullptr) {}
    
    //UDPLayer Constructor
    UDPLayer(const uint8_t *packet);

    void print() const;

    size_t header_size() const;

};


