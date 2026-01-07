add_library(capture
    src/raw-capture.cpp
)

target_include_directories(capture
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(capture
    PUBLIC parser
)
