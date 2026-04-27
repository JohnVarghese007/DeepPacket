#include "dp/core/capture_controller.hpp"
#include "dp/pcap/pcap_reader.hpp"
#include "dp/pcap/pcap_writer.hpp"

#include <chrono>
#include <span>
#include <arpa/inet.h>

using namespace std::chrono;

namespace dp::core {

namespace {

// Map parser IP protocol to GUI-facing TransportProtocol.
TransportProtocol to_transport_protocol(dp::parser::IpProto proto)
{
    switch (proto) {
        case dp::parser::IpProto::TCP:  return TransportProtocol::TCP;
        case dp::parser::IpProto::UDP:  return TransportProtocol::UDP;
        case dp::parser::IpProto::ICMPv4: return TransportProtocol::ICMPv4;
        case dp::parser::IpProto::ICMPv6: return TransportProtocol::ICMPv6;
        default:           return TransportProtocol::UNKNOWN;
    }
}

// Derive ValidationStatus from a PacketValidator.
// Adjust this to match your actual PacketValidator API.
ValidationStatus to_validation_status(const dp::validation::PacketValidator& validator)
{
    for(auto err : validator.errors) {
        if(err!= dp::validation::ValidationError::NONE){
            return ValidationStatus::ERROR;
        }
    }

    return ValidationStatus::OK; 
}

} // anonymous namespace

// ----------------------
// CaptureController
// ----------------------

CaptureController::CaptureController()
    : capture(nullptr),
      mode_(CaptureMode::NONE)
{
    summaries.reserve(4096);
    raw_packets.reserve(4096);
}

CaptureController::~CaptureController()
{
    stop_capture();
}

bool CaptureController::start_live_capture(const std::string& interface)
{
    // For now, SocketCapture is default-constructed and is assumed to
    // bind to the appropriate interface internally. If you later add
    // an interface-aware constructor, wire it up here.
    capture = std::make_unique<dp::capture::SocketCapture>(interface);

    if (!capture->valid()) {
        capture.reset();
        mode_ = CaptureMode::NONE;
        return false;
    }

    mode_ = CaptureMode::LIVE;
    start_polling();
    // You can reset stats/summaries here if you want a fresh session:
    // clear_summaries();
    // reset_stats();
    return true;
}

std::vector<std::string> CaptureController::list_interfaces() const
{
    return dp::capture::SocketCapture::list_interfaces();
}

void CaptureController::stop_capture()
{
    stop_polling();
    mode_ = CaptureMode::NONE;
    capture.reset();
}

bool CaptureController::start_pcap_ingest(const std::string& filename) {
    // stop live capture if currently running
    stop_capture();

    // load pcap file
    dp::pcap::Reader reader(filename);
    if (!reader.valid()) {
        return false;
    }

    std::vector<dp::pcap::Packet> packets;
    if (!reader.read_all(packets)) {
        return false;
    }

    // reset state
    {
        std::scoped_lock lock(summaries_mutex, stats_mutex);
        summaries.clear();
        raw_packets.clear();
        stats = CaptureStats{};
    }

    mode_ = CaptureMode::PCAP;

    // Process packets synchronously
    for (const auto& pkt : packets) {
        const uint8_t* data = pkt.data.data();
        size_t len = pkt.data.size();

        // Parse
        dp::parser::ParsedPacket parsed = dp::parser::parse_packet(std::span<const uint8_t>(data, len));

        // Validate
        dp::validation::PacketValidator validator(parsed.view);

        // Build summary
        PacketSummary summary = make_summary(parsed, validator);
        summary.ts_sec = pkt.ts_sec;
        summary.ts_usec = pkt.ts_usec;

        // store summary and raw bytes
        {
            std::scoped_lock lock(summaries_mutex);
            summaries.push_back(summary);
            raw_packets.emplace_back(data, data + len);
        }

        // Update stats
        {
            std::scoped_lock lock(stats_mutex);
            stats.packets_captured++;
            stats.packets_parsed++;
            stats.packets_validated++;
        }
    }

    return true;
}



bool CaptureController::export_pcap(const std::string& filename) const
{
    if (raw_packets.empty()) {
        return false;
    }

    dp::pcap::Writer writer(filename);
    if (!writer.valid()) {
        return false;
    }

    std::scoped_lock lock(summaries_mutex);

    for (size_t i = 0; i < raw_packets.size(); i++) {
        const auto& bytes = raw_packets[i];
        const auto& summary = summaries[i];

        writer.write_packet(
            bytes.data(),
            bytes.size(),
            summary.ts_sec,
            summary.ts_usec
        );
    }

    return true;
}



void CaptureController::poll()
{
    if (mode_ != CaptureMode::LIVE || !capture) {
        return;
    }

    // Consumer side of the SPSC ring buffer.
    // Process a bounded amount per frame so UI remains responsive under load.
    constexpr std::size_t kMaxPacketsPerPoll = 256;
    static thread_local std::vector<dp::capture::SocketCapture::Packet> batch;
    const std::size_t count = capture->pop_batch(batch, kMaxPacketsPerPoll);

    for (std::size_t i = 0; i < count; ++i) {
        const dp::capture::SocketCapture::Packet& pkt = batch[i];
        if (pkt.len == 0 || pkt.data.empty()) {
            continue;
        }
        process_packet(pkt.data.data(), pkt.len);
    }
}

void CaptureController::start_polling() {
    if (poll_running) return; // already running

    poll_running = true;
    poll_thread = std::thread([this]() {
        while (poll_running) {
            this->poll();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });
}

void CaptureController::stop_polling() {
    poll_running = false;
    if (poll_thread.joinable()) {
        poll_thread.join();
    }
}


std::vector<PacketSummary> CaptureController::get_summaries_snapshot() const
{
    std::lock_guard<std::mutex> lock(summaries_mutex);
    return summaries;   // safe copy
}


CaptureStats CaptureController::get_stats() const
{
    CaptureStats result;

    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        result = stats;
    }

    // Merge in live capture stats from SocketCapture if available.
    if (capture) {
        auto live = capture->get_stats();
        result.packets_captured = live.received;
        result.packets_dropped  = live.dropped;
        // You could also expose errors in CaptureStats later if desired.
    }

    return result;
}

void CaptureController::set_mode(CaptureMode m)
{
    mode_ = m;
}

CaptureMode CaptureController::mode() const
{
    return mode_;
}

dp::parser::PacketView CaptureController::get_packet_view(size_t index) const
{
    std::lock_guard<std::mutex> lock(summaries_mutex);

    if (index >= raw_packets.size()) {
        // Return an empty/invalid PacketView. Adjust to your actual API.
        return dp::parser::PacketView(nullptr, 0);
    }

    const auto& bytes = raw_packets[index];
    return dp::parser::PacketView(bytes.data(), bytes.size());
}

void CaptureController::clear_summaries()
{
    std::lock_guard<std::mutex> lock(summaries_mutex);
    summaries.clear();
    raw_packets.clear();
}

void CaptureController::reset_stats()
{
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats = CaptureStats{};
}

void CaptureController::process_packet(const uint8_t* data, size_t len)
{
    // Parse
    dp::parser::ParsedPacket pkt = dp::parser::parse_packet(std::span<const uint8_t>(data, len));

    // Mark live-capture packets so validator can skip UDP/TCP checksum(to counter checksum offloading effects)
    if(mode_ == CaptureMode::LIVE) {
        pkt.view.is_live_capture = true;
    }
    // Validate
    dp::validation::PacketValidator validator(pkt.view);

    // Build summary
    PacketSummary summary = make_summary(pkt, validator);

    {
        std::lock_guard<std::mutex> lock(summaries_mutex);
        summaries.push_back(std::move(summary));
        raw_packets.emplace_back(data, data + len);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.packets_parsed++;
        stats.packets_validated++;
    }
}

PacketSummary CaptureController::make_summary(const dp::parser::ParsedPacket& pkt, const dp::validation::PacketValidator& validator) const
{
    PacketSummary s;

    // Timestamp: use wall-clock microseconds since epoch for now.
    auto now = system_clock::now().time_since_epoch();
    s.timestamp = duration_cast<microseconds>(now);

    const dp::parser::PacketView& view = pkt.view;

    // IPv4 addresses (if present)
    if(view.has_ipv4 && view.ipv4_layer.iph) {
        char src_buf[INET_ADDRSTRLEN] = {};
        char dst_buf[INET_ADDRSTRLEN] = {};

        inet_ntop(AF_INET, &view.ipv4_layer.iph->src_addr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &view.ipv4_layer.iph->dest_addr, dst_buf, sizeof(dst_buf));

        s.src_ip = src_buf;
        s.dst_ip = dst_buf;
        s.hop_limit_or_ttl = view.ipv4_layer.iph->ttl;
    } 
    else if(view.has_ipv6 && view.ipv6_layer.iph) {
        char src_buf[INET6_ADDRSTRLEN] = {};
        char dst_buf[INET6_ADDRSTRLEN] = {};

        inet_ntop(AF_INET6, view.ipv6_layer.iph->src_addr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, view.ipv6_layer.iph->dest_addr, dst_buf, sizeof(dst_buf));

        s.src_ip = src_buf;
        s.dst_ip = dst_buf;
        s.hop_limit_or_ttl = view.ipv6_layer.iph->hop_limit;
    }
    else if(view.has_arp) {
        s.src_ip = "ARP";
        s.dst_ip = "ARP";
        s.hop_limit_or_ttl = 0;
    }
    else {
        s.src_ip = "N/A";
        s.dst_ip = "N/A";
        s.hop_limit_or_ttl = 0;
    }

    // Ports (if TCP/UDP present) + TCP flags (if TCP)
    s.src_port = 0;
    s.dst_port = 0;
    s.tcp_flags = 0;

    if (view.has_tcp && view.tcp_layer.tcph) {
        s.src_port = ntohs(view.tcp_layer.tcph->src_port);
        s.dst_port = ntohs(view.tcp_layer.tcph->dest_port);
        s.tcp_flags = view.tcp_layer.tcph->flags; 
    } 
    else if (view.has_udp && view.udp_layer.udph) {
        s.src_port = ntohs(view.udp_layer.udph->src);
        s.dst_port = ntohs(view.udp_layer.udph->dest);
        s.tcp_flags = 0;
    } 

    // ICMP type and code    
    s.icmp_type = 0;
    s.icmp_code = 0;

    if (view.has_icmpv4 && view.icmpv4_layer.icmph) {
        s.icmp_type = view.icmpv4_layer.icmph->type;
        s.icmp_code = view.icmpv4_layer.icmph->code;
    }
    else if (view.has_icmpv6 && view.icmpv6_layer.icmph) {
        s.icmp_type = view.icmpv6_layer.icmph->type;
        s.icmp_code = view.icmpv6_layer.icmph->code;
    }

    // IP Protocol classification
    if(view.has_arp) {
        s.protocol = TransportProtocol::ARP; // Since ARP is detected at the ethernet layer
    }
    else {
        s.protocol = to_transport_protocol(view.ip_proto);
    }

    // Packet length
    s.length = static_cast<uint32_t>(view.size());

    // Validation result
    s.validation = to_validation_status(validator);

    return s;
}


} // namespace dp::core