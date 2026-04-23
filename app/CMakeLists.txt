# New ImGui/GLFW/OpenGL frontend
add_executable(DeepPacketUI
    src/ui_main.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_draw.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_tables.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/imgui_widgets.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends/imgui_impl_glfw.cpp
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends/imgui_impl_opengl3.cpp
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialog/ImGuiFileDialog.cpp
)

target_include_directories(DeepPacketUI PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/imgui
    ${CMAKE_SOURCE_DIR}/third_party/imgui/backends
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialog
    ${CMAKE_SOURCE_DIR}/third_party/ImGuiFileDialogConfig

)

find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

target_link_libraries(DeepPacketUI
    PRIVATE
        glfw
        OpenGL::GL
        parser
        validation
        capture
        serialization
        core
)
