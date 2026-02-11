#include "serialization.hpp"
#include <arpa/inet.h>
#include <sstream>


static std::string format_mac(const uint8_t *mac){
    char buf[50];
    snprintf(buf, sizeof(buf),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return std::string(buf);
}

static std::string format_ip(uint32_t ip) {
    char buf[50];   
    ip = ntohl(ip);
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
    return std::string(buf);
}

static uint32_t read_ipv4_from_bytes(const uint8_t* ip_bytes) {
    return (uint32_t(ip_bytes[0]) << 24) |
           (uint32_t(ip_bytes[1]) << 16) |
           (uint32_t(ip_bytes[2]) << 8)  |
           (uint32_t(ip_bytes[3]));
}


nlohmann::json packet_to_json(PacketView& view, PacketValidator& validator) {
    nlohmann::json j;

    j["metadata"] = {
        {"timestamp", "0000-00-00T00:00:00Z"},
        {"packet_index", "undefined"}
    };


    std::string protocol = "UNKNOWN";
    if (view.l4_type == L4Type::TCP) protocol = "TCP";
    else if (view.l4_type == L4Type::UDP) protocol = "UDP";
    else if (view.l4_type == L4Type::ICMP) protocol = "ICMP";

    // summary
    std::string status;
    if(validator.errors.empty()) {
        status = "Packet has not been validated";
    }
    else if(validator.errors.size() == 1 && validator.errors[0] == ValidationError::NONE) {
        status = "OK";
    }
    else {    
        status = "ERROR";
    }
    j["summary"] = {
        {"protocol", protocol},
        {"length", view.length},
        {"validation_status", status}
    };


    // validation
    nlohmann::json error_list = nlohmann::json::array();
    for(ValidationError err : validator.errors) {
        error_list.push_back(to_string(err));
    }

    j["validation"] = {
        {"status", status},
        {"errors", error_list}
    };


    // layers
    auto& layers = j["layers"];
    if(view.has_eth) {
        layers["ethernet"] = {
            {"src_mac", format_mac(view.eth_layer.eth->src_mac)},
            {"dst_mac", format_mac(view.eth_layer.eth->dest_mac)},
            {"ethertype", view.eth_layer.eth->ether_type}
        };
    }
    if(view.has_ip) {
        layers["ipv4"] = {
            {"src_ip", format_ip(view.ip_layer.iph->src_addr)},
            {"dst_ip", format_ip(view.ip_layer.iph->dest_addr)},
            {"ttl", view.ip_layer.iph->ttl},
            {"protocol", view.ip_layer.iph->protocol},
            {"total_length", view.ip_layer.iph->total_length}
        };
    }
    if(view.has_arp) {
        layers["arp"] = {
            {"hardware_type", view.arp_layer.arp->hardware_type},
            {"protocol_type", view.arp_layer.arp->protocol_type},
            {"hardware_length", view.arp_layer.arp->hardware_len},
            {"protocol_length", view.arp_layer.arp->protocol_len},
            {"opcode", view.arp_layer.arp->opcode},
            {"src_mac", format_mac(view.arp_layer.arp->sender_mac)},
            {"src_ip", format_ip(read_ipv4_from_bytes(view.arp_layer.arp->sender_ip))},
            {"dest_mac", format_mac(view.arp_layer.arp->target_mac)},
            {"dest_ip", format_ip(read_ipv4_from_bytes(view.arp_layer.arp->target_ip))}
        };
    }
    if(view.has_tcp) {
        layers["tcp"] = {
            {"src_port", view.tcp_layer.tcph->src_port},
            {"dst_port", view.tcp_layer.tcph->dest_port},
            {"seq", view.tcp_layer.tcph->seq_num},
            {"ack", view.tcp_layer.tcph->ack_num},
            {"flags", view.tcp_layer.tcph->flags}
        };
    }
    if(view.has_udp) {
        layers["udp"] = {
            {"src_port", view.udp_layer.udph->src},
            {"dst_port", view.udp_layer.udph->dest},
            {"length", view.udp_layer.udph->length}
        };
    }
    if(view.has_icmp) {
        layers["icmp"] = {
            {"type", view.icmp_layer.icmph->type},
            {"code", view.icmp_layer.icmph->code}
        };
    }
    // Raw bytes
    j["raw"] = {
        {"bytes", std::vector<uint8_t>(view.data, view.data + view.length)}
    };
    return j;
}



std::string packet_to_json_string(PacketView& v, PacketValidator& validator)  {
    return packet_to_json(v, validator).dump(4);
}