add_library(core
    src/capture_controller.cpp
    src/packet_summary.cpp
)

target_include_directories(core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(core
    PUBLIC
        capture
        parser
        validation
        pcap
)
