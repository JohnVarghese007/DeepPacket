add_executable(DeepPacket
    src/main.cpp
)

target_link_libraries(DeepPacket
    PRIVATE
        parser
        validation
        capture
)
