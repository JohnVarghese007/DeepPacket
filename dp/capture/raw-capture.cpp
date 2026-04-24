#include <iostream>
#include <vector>
#include <cstring>
#include "raw-capture.hpp"
//#include "spsc_ring_buffer.hpp"

/* 
    This is an implementation of the SocketCapture class
*/


namespace dp::capture {

SocketCapture::SocketCapture(const std::string& interface_name) {
    sock = create_socket();
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Bind to specific interface
    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(interface_name.c_str());

    if (sll.sll_ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        sock = -1;
        return;
    }

    if (bind(sock, (sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        sock = -1;
        return;
    }

    // Start async capture thread
    running = true;
    capture_thread = std::thread(&SocketCapture::capture_loop, this);


}


// Destructor
SocketCapture::~SocketCapture() {
    running = false;
    // unblocking recvfrom() by closing socket
    if(sock >= 0){
        close(sock);
    }
    
    if(capture_thread.joinable()) {
        capture_thread.join();
    }    
}

// If returned  value < 0, then socket creation failed
int SocketCapture::create_socket(){
    return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    
}

// make sure to check if socket has been created before calling this function
ssize_t SocketCapture::read_frame(uint8_t* out, std::size_t max_len){
    ssize_t bytes = -1;
    if(sock >= 0){
        bytes = recvfrom(sock, out, max_len, 0, nullptr, nullptr);
    }
    return bytes;
}


// NEW API FOR ASYNC CAPTURE USING THREADS

// producer
void SocketCapture::capture_loop() {
    while (running) {
        Packet pkt;
        ssize_t n = recvfrom(sock, pkt.data.data(), MAX_PACKET_SIZE, 0, nullptr, nullptr);

        if (n <= 0) {
            stats_errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        pkt.len = static_cast<size_t>(n);
        pkt.data.resize(pkt.len);
        // Try to push; if full, drop packet

        if(ring.push(std::move(pkt))) {
            stats_received.fetch_add(1, std::memory_order_relaxed);
        } else {
            stats_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }
}


// consumer
bool SocketCapture::pop_packet(uint8_t* out, size_t& len) {
    Packet pkt;
    if (!ring.pop(pkt))
        return false;

    len = pkt.len;
    std::memcpy(out, pkt.data.data(), len);
    return true;
}

bool SocketCapture::pop_packet(Packet& out) {
    return ring.pop(out);
}

std::size_t SocketCapture::pop_batch(std::vector<Packet>& out, std::size_t max_packets) {
    out.clear();
    if (max_packets == 0) {
        return 0;
    }

    out.reserve(max_packets);
    return ring.pop_batch(std::back_inserter(out), max_packets);
}


SocketCapture::LiveCaptureStats SocketCapture::get_stats() const {
    LiveCaptureStats out;
    out.received = stats_received.load(std::memory_order_relaxed);
    out.dropped = stats_dropped.load(std::memory_order_relaxed);
    out.errors = stats_errors.load(std::memory_order_relaxed);
    return out;
}

std::vector<std::string> SocketCapture::list_interfaces() {
    std::vector<std::string> interfaces;

    struct if_nameindex* all = ::if_nameindex();
    if (!all) {
        return interfaces;
    }

    for (struct if_nameindex* entry = all; entry->if_index != 0 && entry->if_name != nullptr; ++entry) {
        if (entry->if_name != nullptr) {
            interfaces.emplace_back(entry->if_name);
        }
    }

    if_freenameindex(all);
    return interfaces;
}


} // namespace dp::capture
