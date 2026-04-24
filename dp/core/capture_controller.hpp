/*
    1)The job of the Capture controller is to manage where the packets come from whether its 
    - Live capture
    - pcap
    - or replay mode or whatever
    * It does not do the capturing itself but rather owns and manages the capture objects

    2) Polls the ring-buffer in live capture (consumer side)
        - Repeatedly checks if packet available
        - pops it
        - sends it to the parser + validation pipeline
    
    3) Convert parsed packets into PacketSummary
    4) Store PacketSummaries in a growing list
    5) Provide batched updates to GUI
    6) Expose stats
    7) Handles mode switching (for v2)
    8) Provide thread-safe access to summaries + stats

*/

#pragma once

#include <vector>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "dp/core/packet_summary.hpp"
#include "dp/capture/raw-capture.hpp"
#include "dp/parser/parser.hpp"
#include "dp/parser/packet_view.hpp"
#include "dp/validation/validation.hpp"



namespace dp {
namespace core {

// Capture modes (v2)
enum class CaptureMode {
    NONE,
    LIVE,
    PCAP
};

// Unified stats struct
struct CaptureStats {
    uint64_t packets_captured = 0;
    uint64_t packets_parsed = 0;
    uint64_t packets_validated = 0;
    uint64_t packets_dropped = 0;
};

class CaptureController {
public:
    CaptureController();
    ~CaptureController();

    // Start/stop live capture
    bool start_live_capture(const std::string& interface);
    void stop_capture();

    // PCAP import + export
    bool start_pcap_ingest(const std::string& filename);
    bool export_pcap(const std::string& filename) const;

    // Interface discovery for UI
    std::vector<std::string> list_interfaces() const;

    // Called by GUI/CLI each frame/tick
    void poll();

    // Accessors
    std::vector<PacketSummary> get_summaries_snapshot() const;

    CaptureStats get_stats() const;

    // Mode switching (v2)
    void set_mode(CaptureMode mode);
    CaptureMode mode() const;

    //for on-demand packetview reconstruction
    dp::parser::PacketView get_packet_view(size_t index) const;

    // Clear/reset
    void clear_summaries();
    void reset_stats();

private:
    // Internal helpers
    void process_packet(const uint8_t* data, size_t len);
    PacketSummary make_summary(const dp::parser::ParsedPacket& pkt, const dp::validation::PacketValidator& validator) const;

    // Raw packet byte storage for reconstructing packetview on demand
    std::vector<std::vector<uint8_t>> raw_packets;

    // Capture source  ( LIVE OR PCAP)
    std::unique_ptr<dp::capture::SocketCapture> capture;
    
    // Summaries
    std::vector<PacketSummary> summaries;
    mutable std::mutex summaries_mutex;

    // Stats
    CaptureStats stats;
    mutable std::mutex stats_mutex;

    CaptureMode mode_ = CaptureMode::NONE;

    // A separate thread for polling live capture to avoid blocking the main thread. Uses atomic flag for clean shutdown.
    std::thread poll_thread;
    std::atomic<bool> poll_running = false;
    void start_polling();
    void stop_polling();

};


} // namespace core
} // namespace dp


