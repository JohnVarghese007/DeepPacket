#include "pcap_reader.hpp"
#include <fstream>
#include <cstring>

#define PCAP_MAGIC_NUMBER_BE 0xa1b2c3d4
#define PCAP_MAGIC_NUMBER_LE 0xd4c3b2a1

// PCAP file format structures as per wireshark's libpcap documentation
#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

static bool is_valid_magic_number(uint32_t val) {
    return val == PCAP_MAGIC_NUMBER_BE || val == PCAP_MAGIC_NUMBER_LE; // valid magic numbers for pcap files
}

// Utility function to swap endianness of a 32-bit integer
static uint32_t swap32(uint32_t val) {
    return ((val & 0x000000FF) << 24) |
           ((val & 0x0000FF00) << 8) |
           ((val & 0x00FF0000) >> 8) |
           ((val & 0xFF000000) >> 24);
}


// Constructor 
PcapReader::PcapReader(const std::string& filename) : filename_(filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.good()) {
        ok_ = false; // file not found/opened
        return; 
    }

    PcapGlobalHeader global_header{};
    file.read(reinterpret_cast<char*>(&global_header), sizeof(global_header));

    if(!file.good() || !is_valid_magic_number(global_header.magic_number)) {
        ok_ = false; // invalid pcap file
        return;
    }

    // detecting endianness based on the magic number
    if (global_header.magic_number == PCAP_MAGIC_NUMBER_LE) {
        is_little_endian_ = true;
    } else if (global_header.magic_number == PCAP_MAGIC_NUMBER_BE) {
        is_little_endian_ = false;   // since it is big-endian, we will need to swap bytes when reading headers and packet data
    }

    ok_ = true; // file is valid
}

bool PcapReader::read_all(std::vector<PcapPacket> &out_packets) {

    if(!ok_) return false; 

    std::ifstream file(filename_, std::ios::binary);
    if(!file.good()) return false; // kinda redundant since i added a check in the constructor, but just in case

    // Skip the global header
    PcapGlobalHeader global_header{};
    file.read(reinterpret_cast<char*>(&global_header), sizeof(global_header));
    if(!file.good()) return false; // error reading global header

    // Read packets until EOF
    while (true) {
        // Read the record header
        PcapRecordHeader record_header{};
        file.read(reinterpret_cast<char*>(&record_header), sizeof(record_header));
        if (!file.good()) break; // EOF

        // Swap bytes if the file is big-endian
        if (!is_little_endian_) {
            record_header.ts_sec = swap32(record_header.ts_sec);
            record_header.ts_usec = swap32(record_header.ts_usec);
            record_header.incl_len = swap32(record_header.incl_len);
            record_header.orig_len = swap32(record_header.orig_len);
        }

        // Sanity check on packet size
        if (record_header.incl_len == 0 || record_header.incl_len > 10'000'000) {
            return false; 
        }

        // Read the packet data
        PcapPacket myPacket{};
        myPacket.ts_sec = record_header.ts_sec;
        myPacket.ts_usec = record_header.ts_usec;
        myPacket.data.resize(record_header.incl_len);

        file.read(reinterpret_cast<char*>(myPacket.data.data()), record_header.incl_len);
        if (!file.good()) return false;

        // Move the packet into the output vector
        out_packets.push_back(std::move(myPacket));
    }

    return true;
}

