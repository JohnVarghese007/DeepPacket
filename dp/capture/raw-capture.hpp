#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <thread>
#include <atomic>
#include <array>
#include <cstring>
#include <vector>
#include <string>
#include "spsc_ring_buffer.hpp" 


namespace dp {
namespace capture {

class SocketCapture {

public:
    static constexpr size_t MAX_PACKET_SIZE = 4096;
    static constexpr size_t RING_CAPACITY  = 1024;  // adjust for memory/thoroughput

    struct LiveCaptureStats {
        size_t received{0};   // packets successfully captured
        size_t dropped{0};    // ring buffer full
        size_t errors{0};     // recvfrom() errors
    };

    struct Packet {
        size_t len;
        std::vector<uint8_t> data;

        Packet()
            : len(0), data(MAX_PACKET_SIZE) {}

        Packet(const Packet&) = delete;
        Packet& operator=(const Packet&) = delete;
        Packet(Packet&&) noexcept = default;
        Packet& operator=(Packet&&) noexcept = default;
    };

    explicit SocketCapture(const std::string& interface_name = "enp0s3");

    // close the socket if opened
    ~SocketCapture();

    // check if socket was created properly
    bool valid() const {return sock >= 0;}

    // Reads into user-provided buffer (Existing blocking API)
    ssize_t read_frame(uint8_t* out, std::size_t max_len);

    // Optional new API for Consumers(GUI)
    bool pop_packet(uint8_t* out, size_t& len);
    bool pop_packet(Packet& out);
    std::size_t pop_batch(std::vector<Packet>& out, std::size_t max_packets);

    // Getter for live capture stats
    LiveCaptureStats get_stats() const;

    // Query available system interfaces
    static std::vector<std::string> list_interfaces();


private:
    int sock;
    static int create_socket();

    // Internal Additions
    std::thread capture_thread;
    std::atomic<bool> running{false};

    std::atomic<size_t> stats_received{0};
    std::atomic<size_t> stats_dropped{0};
    std::atomic<size_t> stats_errors{0};


    // Lock-free SPSC Ring Buffer
    dp::capture::util::SPSCRingBuffer<Packet> ring{RING_CAPACITY};

    // Producer thread function
    void capture_loop();

};


} // namespace capture
} // namespace dp