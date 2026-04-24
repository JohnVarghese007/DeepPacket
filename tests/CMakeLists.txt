add_executable(deeppacket-tests
    test.cpp
)

target_include_directories(deeppacket-tests PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(deeppacket-tests PRIVATE
    dp_engine
)
