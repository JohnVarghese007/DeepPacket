cmake_minimum_required(VERSION 3.20)

add_executable(dpctl
    dpctl_main.cpp
)

target_link_libraries(dpctl
    PRIVATE
        dp_engine
)
