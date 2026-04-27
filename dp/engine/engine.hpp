#pragma once

#include <string>
#include <vector>
#include <span>
#include <cstdint>

#include "dp/core/capture_controller.hpp"
#include "dp/parser/parser.hpp"
#include "dp/parser/packet_view.hpp"
#include "dp/validation/validation.hpp"

namespace dp {

class DeepPacketEngine {
public:
    DeepPacketEngine();
    ~DeepPacketEngine();

    // Start/stop live capture on a given interface 
    // (linux only for now, can be extended by modifying the parser module to support windows/mac)
    bool start_live_capture(const std::string& interface);
    void stop_capture();

    // PCAP import + export
    bool start_pcap_ingest(const std::string& filename);
    bool export_pcap(const std::string& filename) const;

    // List available interfaces for live capture (linux only for now)
    std::vector<std::string> list_interfaces() const;

    // Drives the capture pipeline once (used by live capture / future modes).
    // For current design, live capture is also driven by an internal thread in CaptureController
    // without having to explicitly call poll(), but keeping this public is useful for tests/CLI/future modes.
    void poll();

    // Get current capture mode (LIVE, PCAP, or NONE)
    dp::core::CaptureMode capture_mode() const;

    // ----- Data Accessors -------- //

    // Get a snapshot of current packet summaries
    std::vector<dp::core::PacketSummary> get_summaries_snapshot() const;

    // Stats snapshot 
    dp::core::CaptureStats get_stats() const;

    // Reconstruct a packet view for a given index
    dp::parser::PacketView get_packet_view(std::size_t index) const;

    // Clear summaries and reset stats 
    void clear();


    // ---- Stateless helpers (direct parsing) ----

    // Parse a raw packet buffer into a ParsedPacket (no capture involved).
    dp::parser::ParsedPacket parse_buffer(std::span<const std::uint8_t> buffer) const;

    // Build a validator for a given PacketView.
    dp::validation::PacketValidator make_validator(const dp::parser::PacketView& view) const;

    
private:
    dp::core::CaptureController controller_;
};



} // namespace dp