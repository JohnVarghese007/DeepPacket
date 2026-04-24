#include "pcap_writer.hpp"
#include <fstream>

/* 
    This file Contrains the implementation of the PcapWriter class
    - Enables .pcap exports for captured packets
    
*/


namespace dp::pcap {

// PCAP file format structures as per wireshark's libpcap documentation
#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t network = 1; // LINKTYPE_ETHERNET
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)


Writer::Writer(const std::string& filename) : filename_(filename) {    
    std::ofstream file(filename_, std::ios::binary);
    if (!file.good()) {
        ok_ = false;
        return;
    }

    PcapGlobalHeader global_header{};
    file.write(reinterpret_cast<const char*>(&global_header), sizeof(global_header));
    ok_ = file.good();
}

bool Writer::write_packet(const uint8_t* data, uint32_t len, uint32_t ts_sec, uint32_t ts_usec) {
    if (!ok_) return false;
    std::ofstream file(filename_, std::ios::binary | std::ios::app);
    if (!file.good()) return false;

    // Creating the record header for the packet
    PcapRecordHeader record_header{};
    record_header.ts_sec = ts_sec;
    record_header.ts_usec = ts_usec;
    record_header.incl_len = len;
    record_header.orig_len = len;

    // Write the record header and packet data to the file
    file.write(reinterpret_cast<const char*>(&record_header), sizeof(record_header));
    file.write(reinterpret_cast<const char*>(data), len);
    file.flush();

    return file.good(); // returns false if there was an error writing the packet data or header
}


} // namespace dp::pcap