add_library(serialization
    src/serialization.cpp
)

target_include_directories(serialization
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(serialization
    PUBLIC
        parser
        validation
)
