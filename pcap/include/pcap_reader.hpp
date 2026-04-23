#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct PcapPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    explicit PcapReader(const std::string& filename);

    bool valid() const {return ok_;}

    // reads all packets into out_packets
    // returns false if there is any kind of error
    bool read_all(std::vector<PcapPacket> &out_packets);

private:
    std::string filename_;
    bool ok_ = false; // set to true if the file was successfully opened and read
    bool is_little_endian_ = false; // set based on the magic number in the global header
};