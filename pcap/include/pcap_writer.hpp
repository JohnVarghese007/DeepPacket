#pragma once
#include <string>
#include <vector>
#include <cstdint>

class PcapWriter {
public:
    explicit PcapWriter(const std::string& filename);

    bool valid() const { return ok_; }

    // Append a packet to the file
    bool write_packet(const uint8_t* data, uint32_t len, uint32_t ts_sec, uint32_t ts_usec);

private:
    std::string filename_;
    bool ok_ = false;
};
