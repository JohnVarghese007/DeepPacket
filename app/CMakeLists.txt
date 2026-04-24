add_executable(deeppacket
    src/ui_main.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_draw.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_tables.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_widgets.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends/imgui_impl_glfw.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends/imgui_impl_opengl3.cpp
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialog/ImGuiFileDialog.cpp
)

target_include_directories(deeppacket PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/imgui
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialog
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialogConfig
)

find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

target_link_libraries(deeppacket PRIVATE
    dp_engine
    glfw
    OpenGL::GL
)
