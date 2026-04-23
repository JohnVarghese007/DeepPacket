add_library(pcap
    src/pcap_reader.cpp
    src/pcap_writer.cpp
)

target_include_directories(pcap
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
