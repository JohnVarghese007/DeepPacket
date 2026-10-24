cmake_minimum_required(VERSION 3.20)
project(DeepPacket LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DEEPPACKET_SANITIZER "OFF" CACHE STRING
    "Sanitizer mode: OFF, ASAN, UBSAN, ASAN_UBSAN, or TSAN")
set_property(CACHE DEEPPACKET_SANITIZER PROPERTY STRINGS
    OFF ASAN UBSAN ASAN_UBSAN TSAN)

string(TOUPPER "${DEEPPACKET_SANITIZER}" DEEPPACKET_SANITIZER)
if (DEEPPACKET_SANITIZER STREQUAL "ASAN")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
elseif (DEEPPACKET_SANITIZER STREQUAL "UBSAN")
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
elseif (DEEPPACKET_SANITIZER STREQUAL "ASAN_UBSAN")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif (DEEPPACKET_SANITIZER STREQUAL "TSAN")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
elseif (NOT DEEPPACKET_SANITIZER STREQUAL "OFF")
    message(FATAL_ERROR
        "Unknown DEEPPACKET_SANITIZER='${DEEPPACKET_SANITIZER}'. "
        "Use OFF, ASAN, UBSAN, ASAN_UBSAN, or TSAN.")
endif()

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
    dp/capture/bpf.cpp

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
