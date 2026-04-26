#include "dp/serialization/serialization.hpp"
#include <arpa/inet.h>
#include <sstream>

namespace {

static std::string format_mac(const uint8_t *mac) {
    char buf[50];
    snprintf(buf, sizeof(buf),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

static std::string format_ipv4_u32(uint32_t ip) {
    char buf[50];
    ip = ntohl(ip);
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
    return std::string(buf);
}

static uint32_t read_ipv4_bytes(const uint8_t* ip_bytes) {
    return (uint32_t(ip_bytes[0]) << 24) |
           (uint32_t(ip_bytes[1]) << 16) |
           (uint32_t(ip_bytes[2]) << 8)  |
           (uint32_t(ip_bytes[3]));
}

static std::string format_ipv6(const uint8_t* addr) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return std::string(buf);
}

} // anonymous namespace


namespace dp::serialization {

nlohmann::json packet_to_json(dp::parser::PacketView& view, dp::validation::PacketValidator& validator) {
    nlohmann::json j;

    j["metadata"] = {
        {"timestamp", "0000-00-00T00:00:00Z"},
        {"packet_index", "undefined"}
    };

    std::string protocol = "UNKNOWN";
    if (view.ip_proto == dp::parser::IpProto::TCP) protocol = "TCP";
    else if (view.ip_proto == dp::parser::IpProto::UDP) protocol = "UDP";
    else if (view.ip_proto == dp::parser::IpProto::ICMPv4) protocol = "ICMPv4";
    else if (view.ip_proto == dp::parser::IpProto::ICMPv6) protocol = "ICMPv6";

    std::string status;
    if (validator.errors.empty()) status = "Packet has not been validated";
    else if (validator.errors.size() == 1 &&
             validator.errors[0] == dp::validation::ValidationError::NONE)
        status = "OK";
    else
        status = "ERROR";

    j["summary"] = {
        {"protocol", protocol},
        {"length", view.size()},
        {"validation_status", status}
    };

    nlohmann::json error_list = nlohmann::json::array();
    for (auto err : validator.errors)
        error_list.push_back(dp::validation::to_string(err));

    j["validation"] = {
        {"status", status},
        {"errors", error_list}
    };

    auto& layers = j["layers"];

    if (view.has_eth) {
        layers["ethernet"] = {
            {"src_mac", format_mac(view.eth_layer.eth->src_mac)},
            {"dst_mac", format_mac(view.eth_layer.eth->dest_mac)},
            {"ethertype", ntohs(view.eth_layer.eth->ether_type)}
        };
    }

    if (view.has_arp) {
        layers["arp"] = {
            {"hardware_type", ntohs(view.arp_layer.arp->hardware_type)},
            {"protocol_type", ntohs(view.arp_layer.arp->protocol_type)},
            {"hardware_length", view.arp_layer.arp->hardware_len},
            {"protocol_length", view.arp_layer.arp->protocol_len},
            {"opcode", ntohs(view.arp_layer.arp->opcode)},
            {"src_mac", format_mac(view.arp_layer.arp->sender_mac)},
            {"src_ip", format_ipv4_u32(read_ipv4_bytes(reinterpret_cast<const uint8_t*>(view.arp_layer.arp->sender_ip)))},
            {"dest_mac", format_mac(view.arp_layer.arp->target_mac)},
            {"dest_ip", format_ipv4_u32(read_ipv4_bytes(reinterpret_cast<const uint8_t*>(view.arp_layer.arp->target_ip)))}
        };
    }

    if (view.has_ipv4) {
        layers["ipv4"] = {
            {"src_ip", format_ipv4_u32(read_ipv4_bytes(reinterpret_cast<const uint8_t*>(view.ipv4_layer.iph->src_addr)))},
            {"dst_ip", format_ipv4_u32(read_ipv4_bytes(reinterpret_cast<const uint8_t*>(view.ipv4_layer.iph->dest_addr)))},
            {"ttl", view.ipv4_layer.iph->ttl},
            {"protocol", view.ipv4_layer.iph->protocol},
            {"total_length", ntohs(view.ipv4_layer.iph->total_length)}
        };
    }

    if (view.has_ipv6) {
        layers["ipv6"] = {
            {"src_ip", format_ipv6(view.ipv6_layer.iph->src_addr)},
            {"dst_ip", format_ipv6(view.ipv6_layer.iph->dest_addr)},
            {"hop_limit", view.ipv6_layer.iph->hop_limit},
            {"next_header", view.ipv6_layer.iph->next_header},
            {"payload_length", ntohs(view.ipv6_layer.iph->payload_length)}
        };
    }

    if (view.has_tcp) {
        layers["tcp"] = {
            {"src_port", ntohs(view.tcp_layer.tcph->src_port)},
            {"dst_port", ntohs(view.tcp_layer.tcph->dest_port)},
            {"seq", ntohl(view.tcp_layer.tcph->seq_num)},
            {"ack", ntohl(view.tcp_layer.tcph->ack_num)},
            {"flags", view.tcp_layer.tcph->flags}
        };
    }

    if (view.has_udp) {
        layers["udp"] = {
            {"src_port", ntohs(view.udp_layer.udph->src)},
            {"dst_port", ntohs(view.udp_layer.udph->dest)},
            {"length", ntohs(view.udp_layer.udph->length)}
        };
    }

    if (view.has_icmpv4) {
        layers["icmpv4"] = {
            {"type", view.icmpv4_layer.icmph->type},
            {"code", view.icmpv4_layer.icmph->code}
        };
    }

    if (view.has_icmpv6) {
        layers["icmpv6"] = {
            {"type", view.icmpv6_layer.icmph->type},
            {"code", view.icmpv6_layer.icmph->code}
        };
    }

    j["raw"] = {
        {"bytes", std::vector<uint8_t>(view.data, view.data + view.size())}
    };

    return j;
}

std::string packet_to_json_string(dp::parser::PacketView& v, dp::validation::PacketValidator& validator)
{
    return packet_to_json(v, validator).dump(4);
}

} // namespace dp::serialization
