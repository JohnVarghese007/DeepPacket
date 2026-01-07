add_library(validation
    src/validation.cpp
)

target_include_directories(validation
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(validation
    PUBLIC parser
)
