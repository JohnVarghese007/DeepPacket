#include "dp/pcap/pcap_reader.hpp"
#include <fstream>
#include <array>
#include <cstring>


namespace dp::pcap { 

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

static uint16_t decode_u16(const uint8_t* bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<uint16_t>(bytes[0]) |
               (static_cast<uint16_t>(bytes[1]) << 8);
    }

    return (static_cast<uint16_t>(bytes[0]) << 8) |
           static_cast<uint16_t>(bytes[1]);
}

static uint32_t decode_u32(const uint8_t* bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<uint32_t>(bytes[0]) |
               (static_cast<uint32_t>(bytes[1]) << 8) |
               (static_cast<uint32_t>(bytes[2]) << 16) |
               (static_cast<uint32_t>(bytes[3]) << 24);
    }

    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}


// Constructor 
Reader::Reader(const std::string& filename) : filename_(filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.good()) {
        ok_ = false; // file not found/opened
        return; 
    }

    std::array<uint8_t, sizeof(PcapGlobalHeader)> global_header{};
    file.read(reinterpret_cast<char*>(global_header.data()), global_header.size());

    if (!file.good()) {
        ok_ = false; // invalid pcap file
        return;
    }

    const auto magic = global_header.data();
    if (magic[0] == 0xD4 && magic[1] == 0xC3 &&
        magic[2] == 0xB2 && magic[3] == 0xA1) {
        file_little_endian_ = true;
    } else if (magic[0] == 0xA1 && magic[1] == 0xB2 &&
               magic[2] == 0xC3 && magic[3] == 0xD4) {
        file_little_endian_ = false;
    } else {
        ok_ = false;
        return;
    }

    const uint16_t version_major = decode_u16(magic + 4, file_little_endian_);
    const uint16_t version_minor = decode_u16(magic + 6, file_little_endian_);
    if (version_major != 2 || version_minor != 4) {
        ok_ = false;
        return;
    }

    ok_ = true; // file is valid
}

bool Reader::read_all(std::vector<Packet> &out_packets) {

    if(!ok_) return false; 

    std::ifstream file(filename_, std::ios::binary);
    if(!file.good()) return false; // kinda redundant since i added a check in the constructor, but just in case

    // Skip the global header
    std::array<uint8_t, sizeof(PcapGlobalHeader)> global_header{};
    file.read(reinterpret_cast<char*>(global_header.data()), global_header.size());
    if(!file.good()) return false; // error reading global header

    out_packets.clear();

    // Read packets until EOF
    while (true) {
        // Read the record header
        std::array<uint8_t, sizeof(PcapRecordHeader)> record_header{};
        file.read(reinterpret_cast<char*>(record_header.data()), record_header.size());
        if (!file.good()) break; // EOF

        const uint32_t ts_sec = decode_u32(record_header.data(), file_little_endian_);
        const uint32_t ts_usec = decode_u32(record_header.data() + 4, file_little_endian_);
        const uint32_t incl_len = decode_u32(record_header.data() + 8, file_little_endian_);

        // Sanity check on packet size
        if (incl_len == 0 || incl_len > 10'000'000) {
            return false; 
        }

        // Read the packet data
        Packet myPacket{};
        myPacket.ts_sec = ts_sec;
        myPacket.ts_usec = ts_usec;
        myPacket.data.resize(incl_len);

        file.read(reinterpret_cast<char*>(myPacket.data.data()), incl_len);
        if (!file.good()) return false;

        // Move the packet into the output vector
        out_packets.push_back(std::move(myPacket));
    }

    return true;
}


} // namespace dp::pcap
