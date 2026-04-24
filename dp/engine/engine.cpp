#include "dp/engine/engine.hpp"


/*
    This is the implementation of the main Engine class that serves as the orchestration interface for the entire packet processing pipeline. 
    It interacts with the CaptureController for live capture and PCAP ingest, 
    uses the parser to reconstruct packet views, and applies validation. 
    The Engine provides a clean API for the GUI/CLI to access summaries, stats, and detailed packet views without needing to know about the underlying modules. 
    It also includes some stateless helper functions for direct parsing/validation which can be useful for CLI tools or tests 
    that want to bypass the capture layer and directly feed raw packet data into the parser/validator.

    It manages the capture controller, parsing, validation, and provides a clean API for the GUI/CLI.

    Responsibilities:
    - Start/stop live capture and PCAP ingest
    - Provide access to packet summaries and stats for the GUI
    - Reconstruct packet views on demand
    - Provide stateless helper functions for direct parsing/validation (useful for CLI/tests)
*/


namespace dp::engine {

Engine::Engine() = default;
Engine::~Engine() = default;

bool Engine::start_live_capture(const std::string& interface) {
    return controller_.start_live_capture(interface);
}

bool Engine::start_pcap_ingest(const std::string& filename) {
    return controller_.start_pcap_ingest(filename);
}

void Engine::stop_capture() {
    controller_.stop_capture();
}

void Engine::poll() {
    controller_.poll();
}

bool Engine::export_pcap(const std::string& filename) const {
    return controller_.export_pcap(filename);
}

std::vector<std::string> Engine::list_interfaces() const {
    return controller_.list_interfaces();
}

// ---- Data access ----

std::vector<dp::core::PacketSummary> Engine::get_summaries_snapshot() const {
    return controller_.get_summaries_snapshot();
}

dp::core::CaptureStats Engine::get_stats() const {
    return controller_.get_stats();
}

dp::parser::PacketView Engine::get_packet_view(std::size_t index) const {
    return controller_.get_packet_view(index);
}

void Engine::clear() {
    controller_.clear_summaries();
    controller_.reset_stats();
}

// ---- Stateless helpers (direct parsing) ----

dp::parser::ParsedPacket Engine::parse_buffer(std::span<const std::uint8_t> buffer) const {
    return dp::parser::parse_packet(buffer);
}

dp::validation::PacketValidator Engine::make_validator(const dp::parser::PacketView& view) const {
    return dp::validation::PacketValidator(view);
}

} // namespace dp::engine

