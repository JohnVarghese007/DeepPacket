#include "capture_controller.hpp"

#include <chrono>
#include <span>
#include <arpa/inet.h>

using namespace std::chrono;

namespace {

// Map parser L4Type to GUI-facing TransportProtocol.
// Adjust the L4Type names to match your actual enum in parser.hpp.
TransportProtocol to_transport_protocol(L4Type l4)
{
    switch (l4) {
        case L4Type::TCP:  return TransportProtocol::TCP;
        case L4Type::UDP:  return TransportProtocol::UDP;
        case L4Type::ICMP: return TransportProtocol::ICMP;
        default:           return TransportProtocol::UNKNOWN;
    }
}

// Derive ValidationStatus from a PacketValidator.
// Adjust this to match your actual PacketValidator API.
ValidationStatus to_validation_status(const PacketValidator& validator)
{
    for(auto err : validator.errors) {
        if(err!= ValidationError::NONE){
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
    capture = std::make_unique<SocketCapture>(interface);

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
    return SocketCapture::list_interfaces();
}

void CaptureController::stop_capture()
{
    stop_polling();
    mode_ = CaptureMode::NONE;
    capture.reset();
}

void CaptureController::poll()
{
    if (mode_ != CaptureMode::LIVE || !capture) {
        return;
    }

    // Consumer side of the SPSC ring buffer.
    // Process a bounded amount per frame so UI remains responsive under load.
    constexpr std::size_t kMaxPacketsPerPoll = 256;
    static thread_local std::vector<SocketCapture::Packet> batch;
    const std::size_t count = capture->pop_batch(batch, kMaxPacketsPerPoll);

    for (std::size_t i = 0; i < count; ++i) {
        const SocketCapture::Packet& pkt = batch[i];
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

PacketView CaptureController::get_packet_view(size_t index) const
{
    std::lock_guard<std::mutex> lock(summaries_mutex);

    if (index >= raw_packets.size()) {
        // Return an empty/invalid PacketView. Adjust to your actual API.
        return PacketView(nullptr, 0);
    }

    const auto& bytes = raw_packets[index];
    return PacketView(bytes.data(), bytes.size());
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
    ParsedPacket pkt = parse_packet(std::span<const uint8_t>(data, len));

    // Validate
    PacketValidator validator(pkt.view);

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

PacketSummary CaptureController::make_summary(const ParsedPacket& pkt, const PacketValidator& validator) const
{
    PacketSummary s;

    // Timestamp: use wall-clock microseconds since epoch for now.
    auto now = system_clock::now().time_since_epoch();
    s.timestamp = duration_cast<microseconds>(now);

    const PacketView& view = pkt.view;

    // IPv4 addresses (if present)
    if (view.has_ip && view.ip_layer.iph) {
        char src_buf[INET_ADDRSTRLEN] = {};
        char dst_buf[INET_ADDRSTRLEN] = {};

        inet_ntop(AF_INET, &view.ip_layer.iph->src_addr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &view.ip_layer.iph->dest_addr, dst_buf, sizeof(dst_buf));

        s.src_ip = src_buf;
        s.dst_ip = dst_buf;
    } else {
        s.src_ip = "N/A";
        s.dst_ip = "N/A";
    }

    // Ports (if TCP/UDP present). Adjust field names to your actual headers.
    s.src_port = 0;
    s.dst_port = 0;

    if (view.has_tcp && view.tcp_layer.tcph) {
        // Typical TCP header fields: src_port, dest_port, flags, etc.
        s.src_port = ntohs(view.tcp_layer.tcph->src_port);
        s.dst_port = ntohs(view.tcp_layer.tcph->dest_port);

        // TCP flags (if you have a flags field).
        s.tcp_flags = view.tcp_layer.tcph->flags; // adjust to your struct
    } else if (view.has_udp && view.udp_layer.udph) {
        s.src_port = ntohs(view.udp_layer.udph->src);
        s.dst_port = ntohs(view.udp_layer.udph->dest);
        s.tcp_flags = 0;
    } else {
        s.tcp_flags = 0;
    }

    // Protocol classification
    s.protocol = to_transport_protocol(view.l4_type);

    // Packet length
    s.length = static_cast<uint32_t>(view.size());

    // Validation result
    s.validation = to_validation_status(validator);

    return s;
}