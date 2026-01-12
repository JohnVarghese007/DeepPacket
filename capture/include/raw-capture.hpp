#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

class SocketCapture {
public:
    SocketCapture();

    // close the socket if opened
    ~SocketCapture();

    // check if socket was created properly
    bool valid() const {return sock >= 0;}

    // Reads into user-provided buffer
    ssize_t read_frame(uint8_t* out, std::size_t max_len);

private:
    int sock;
    static int create_socket();
};
