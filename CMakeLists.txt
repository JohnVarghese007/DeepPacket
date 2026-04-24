cmake_minimum_required(VERSION 3.20)
project(DeepPacket LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable warnings
if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# -----------------------------
# Engine Library (dp_engine)
# -----------------------------
add_library(dp_engine
    dp/core/capture_controller.cpp
    dp/core/packet_summary.cpp

    dp/parser/layers.cpp
    dp/parser/packet_view.cpp
    dp/parser/parser.cpp

    dp/validation/packet-error.cpp
    dp/validation/validation.cpp

    dp/capture/raw-capture.cpp

    dp/pcap/pcap_reader.cpp
    dp/pcap/pcap_writer.cpp

    dp/serialization/serialization.cpp

    dp/engine/engine.cpp
)

target_include_directories(dp_engine PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/dp
)

# -----------------------------
# Subdirectories
# -----------------------------
add_subdirectory(app)
add_subdirectory(tests)
add_subdirectory(cli)
