#pragma once
#include "packet_view.hpp"
#include "packet-error.hpp"
#include <vector>

class PacketValidator {
public:
    const PacketView& view;
    std::vector<ValidationError> errors;
    
    PacketValidator(const PacketView& v) 
        : view(v)
    {
        validate_packet();
    }

    
    void validate_packet();

    void print_errors() const;
    void print_raw_packet_bytes() const; 


private:
    static bool validate_ethernet(const PacketView& view, ValidationError& error);
    static bool validate_ipv4(const PacketView& view, ValidationError& error);
    static bool validate_tcp(const PacketView& view, ValidationError& error);
    static bool validate_udp(const PacketView& view, ValidationError& error);
    

};



