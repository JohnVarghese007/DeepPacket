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
#include "spsc_ring_buffer.hpp" 


class SocketCapture {
public:
    SocketCapture();

    // close the socket if opened
    ~SocketCapture();

    // check if socket was created properly
    bool valid() const {return sock >= 0;}

    // Reads into user-provided buffer (Existing blocking API)
    ssize_t read_frame(uint8_t* out, std::size_t max_len);

    // Optional new API for Consumers(GUI)
    bool pop_packet(uint8_t* out, size_t& len);



private:
    int sock;
    static int create_socket();

    // Internal Additions
    std::thread capture_thread;
    std::atomic<bool> running{false};

    static constexpr size_t MAX_PACKET_SIZE = 4096;
    static constexpr size_t RING_CAPACITY  = 1024;  // adjust for memory/thoroughput

    // Lock-free SPSC Ring Buffer
    spsc_ring_buffer<uint8_t[RING_CAPACITY][MAX_CAPACITY]> ring;

    // Producer thread function
    void capture_loop();

};
