add_executable(deeppacket-tests
    test.cpp
)

target_include_directories(deeppacket-tests PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(deeppacket-tests PRIVATE
    dp_engine
)

add_executable(deeppacket-bpf-tests
    bpf_compiler_tests.cpp
)

target_include_directories(deeppacket-bpf-tests PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(deeppacket-bpf-tests PRIVATE
    dp_engine
)