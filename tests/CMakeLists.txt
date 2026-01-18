add_executable(DeepPacketTests
    test.cpp
)

target_link_libraries(DeepPacketTests
    PRIVATE
        parser
        validation
        capture
)
