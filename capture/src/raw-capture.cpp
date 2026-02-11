#include <iostream>
#include <vector>
#include "raw-capture.hpp"

/* 
    This is an implementation of the SocketCapture class
*/

SocketCapture::SocketCapture() {
    sock = create_socket();
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Bind to specific interface: enp0s8
    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex("enp0s3");

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

}


// Destructor
SocketCapture::~SocketCapture() {
    if(sock >= 0){
        close(sock);
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

