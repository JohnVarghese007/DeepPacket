#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>

#include "dp/engine/engine.hpp"

static volatile bool g_stop = false;

// ------------------------------------------------------------
// Terminal raw mode for non-blocking input during live capture
// ------------------------------------------------------------
void set_nonblocking_terminal(bool enable) {
    static struct termios oldt;
    struct termios newt;

    if (enable) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    } else {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fcntl(STDIN_FILENO, F_SETFL, 0);
    }
}

void handle_sigint(int) {
    g_stop = true;
}

static void print_info() {
    std::cout <<
        "DeepPacket CLI (dpctl)\n"
        "Version: 1.0.0\n"
        "Description: Zero-copy packet inspection tool for live capture and PCAP analysis.\n"
        "Commands:\n"
        "  interfaces              List available network interfaces\n"
        "  live <iface>            Start live capture\n"
        "  stop                    Stop live capture\n"
        "  read <pcap>             Load and summarize a PCAP file\n"
        "  view <index>            Show detailed packet breakdown\n"
        "  export <pcap>           Export current capture to PCAP\n"
        "  info                    Show engine/system info\n"
        "  help                    Show this help message\n"
        "  quit / exit             Leave dpctl\n";
}

int main() {
    dp::DeepPacketEngine DeepPacketEngine;

    std::cout << "DeepPacket CLI (interactive mode)\n";
    std::cout << "Type 'help' for commands.\n";

    std::string line;
    bool live_running = false;

    while (true) {
        std::cout << "dpctl> ";
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        if (line == "quit" || line == "exit") {
            std::cout << "Goodbye.\n";
            break;
        }

        if (line == "help") {
            print_info();
            continue;
        }

        if (line == "info") {
            print_info();
            continue;
        }

        if (line == "interfaces") {
            auto interfaces = DeepPacketEngine.list_interfaces();
            for (auto& iface : interfaces)
                std::cout << "  - " << iface << "\n";
            continue;
        }

        if (line == "stop") {
            if (!live_running) {
                std::cout << "No live capture running.\n";
                continue;
            }
            DeepPacketEngine.stop_capture();
            live_running = false;
            g_stop = false;
            set_nonblocking_terminal(false);
            std::cout << "Live capture stopped.\n";
            continue;
        }

        // ------------------------------------------------------------
        // LIVE CAPTURE
        // ------------------------------------------------------------
        if (line.rfind("live ", 0) == 0) {
            std::string iface = line.substr(5);

            if (!DeepPacketEngine.start_live_capture(iface)) {
                std::cerr << "Failed to start live capture on " << iface << "\n";
                continue;
            }

            std::cout << "Live capture on " << iface << " (type 'stop' to end)\n";
            live_running = true;
            g_stop = false;

            set_nonblocking_terminal(true);

            std::string input_buffer;
            // Track last printed packet index to only show new packets
            size_t last_printed = (size_t)-1; 

            while (!g_stop) {
                DeepPacketEngine.poll();

                // -----------------------------
                // Non-blocking input for "stop"
                // -----------------------------
                char c;
                while (read(STDIN_FILENO, &c, 1) > 0) {
                    if (c == '\n') {
                        if (input_buffer == "stop") {
                            g_stop = true;
                            break;
                        }
                        input_buffer.clear();
                    } else {
                        input_buffer.push_back(c);
                    }
                }

                // -----------------------------
                // Print ALL packets since last poll
                // -----------------------------
                auto summaries = DeepPacketEngine.get_summaries_snapshot();
                size_t count = summaries.size();

                if (count > 0) {
                    // print every new packet
                    for (size_t i = last_printed + 1; i < count; ++i) {
                        const auto& s = summaries[i];

                        std::cout << "#" << i << "  "
                                << s.src_ip << " -> " << s.dst_ip
                                << "  " << dp::core::transport_proto_to_string(s.protocol)
                                << "  LEN " << s.length
                                << "  " << (s.validation == dp::core::ValidationStatus::OK ? "OK" : "INVALID")
                                << "\n";
                    }

                    last_printed = count - 1;
                }

                usleep(5000); // 5ms is smooth + low CPU
            }

            set_nonblocking_terminal(false);

            DeepPacketEngine.stop_capture();
            live_running = false;
            g_stop = false;
            set_nonblocking_terminal(false);

            std::cout << "Capture stopped.\n";
            continue;
        }

        // ------------------------------------------------------------
        // READ PCAP
        // ------------------------------------------------------------
        if (line.rfind("read ", 0) == 0) {
            std::string file = line.substr(5);

            if (!DeepPacketEngine.start_pcap_ingest(file)) {
                std::cerr << "Failed to read PCAP: " << file << "\n";
                continue;
            }

            auto summaries = DeepPacketEngine.get_summaries_snapshot();
            for (size_t i = 0; i < summaries.size(); ++i) {
                const auto& s = summaries[i];
                std::cout << "#" << i << "  "
                          << s.src_ip << " -> " << s.dst_ip
                          << "  " << dp::core::transport_proto_to_string(s.protocol)
                          << "  LEN " << s.length
                          << "  " << (s.validation == dp::core::ValidationStatus::OK ? "OK" : "INVALID")
                          << "\n";
            }
            continue;
        }

        // ------------------------------------------------------------
        // VIEW PACKET
        // ------------------------------------------------------------
        if (line.rfind("view ", 0) == 0) {
            size_t idx = std::stoul(line.substr(5));

            auto view = DeepPacketEngine.get_packet_view(idx);
            auto validator = DeepPacketEngine.make_validator(view);

            std::cout << view.to_string();
            std::cout << validator.to_string();
            continue;
        }

        // ------------------------------------------------------------
        // EXPORT PCAP
        // ------------------------------------------------------------
        if (line.rfind("export ", 0) == 0) {
            std::string file = line.substr(7);

            if (!DeepPacketEngine.export_pcap(file)) {
                std::cerr << "Failed to export PCAP.\n";
            } else {
                std::cout << "Exported to " << file << "\n";
            }
            continue;
        }

        std::cout << "Unknown command. Type 'help'.\n";
    }

    return 0;
}
