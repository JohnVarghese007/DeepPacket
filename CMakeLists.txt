cmake_minimum_required(VERSION 3.20)
project(DeepPacket)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable warnings
if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Add subdirectories
add_subdirectory(parser)
add_subdirectory(validation)
add_subdirectory(capture)
add_subdirectory(app)
