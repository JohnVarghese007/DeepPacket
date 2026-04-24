#pragma once
#include "dp/parser/packet_view.hpp"
#include "dp/validation/packet-error.hpp"
#include <vector>


namespace dp {
namespace validation {

class PacketValidator {
public:
    const dp::parser::PacketView& view;
    std::vector<ValidationError> errors;
    
    PacketValidator(const dp::parser::PacketView& v) 
        : view(v)
    {
        validate_packet();
    }
    
    void validate_packet();
    void print_errors(std::ostream& os) const;
    void print_raw_packet_bytes(std::ostream& os) const; 


private:
    static bool validate_ethernet(const dp::parser::PacketView& view, ValidationError& error);
    static bool validate_arp(const dp::parser::PacketView& view, ValidationError& error);
    static bool validate_ipv4(const dp::parser::PacketView& view, ValidationError& error);
    static bool validate_tcp(const dp::parser::PacketView& view, ValidationError& error);
    static bool validate_udp(const dp::parser::PacketView& view, ValidationError& error);
    static bool validate_icmp(const dp::parser::PacketView& view, ValidationError& error);    
};


} // namespace validation
} // namespace dp


