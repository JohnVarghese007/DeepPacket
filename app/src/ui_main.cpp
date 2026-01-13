#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include <chrono>
#include  <ctime>

#include <vector>
#include <string>
#include <sstream>
#include <iostream>

#include "raw-capture.hpp"
#include "parser.hpp"
#include "validation.hpp"

struct RowData {
    std::string timestamp;
    std::string parsed_output;
    std::string validation_output;
};

static std::string now_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
    return buf;
}

int main() {
    if (!glfwInit()) {
        return -1;
    }

    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
    const GLFWvidmode* mode = glfwGetVideoMode(monitor);

    GLFWwindow* window = glfwCreateWindow(
        mode->width, mode->height,
        "DeepPacket UI",
        monitor, nullptr
    );

    if (!window) {
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // Start/stop button to determine capture state
    SocketCapture capture;
    bool capturing = false;

    constexpr std::size_t MAX_FRAME_SIZE = 65536;
    std::vector<uint8_t> buffer(MAX_FRAME_SIZE);

    std::vector<RowData> rows;

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("DeepPacket UI",
                     nullptr,
                     ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoCollapse);

        // Start/Stop button
        if (ImGui::Button(capturing ? "Stop Capture" : "Start Capture")) {
            capturing = !capturing;
        }

        ImGui::Separator();

        // ---------------- Capture Logic ----------------
        if (capturing && capture.valid()) {
            ssize_t bytes = capture.read_frame(buffer.data(), buffer.size());

            if (bytes > 0) {
                // Parse packet
                ParsedPacket pkt = parse_packet(
                    std::span<const uint8_t>(buffer.data(), bytes)
                );

                // Capture printed parser output
                std::stringstream parser_ss;
                {
                    std::streambuf* old = std::cout.rdbuf(parser_ss.rdbuf());
                    pkt.view.print();
                    std::cout.rdbuf(old);
                }

                // Capture printed validation output
                PacketValidator validator(pkt.view);
                std::stringstream val_ss;
                {
                    std::streambuf* old = std::cout.rdbuf(val_ss.rdbuf());
                    validator.print_errors();
                    std::cout.rdbuf(old);
                }

                rows.push_back({
                    now_timestamp(),
                    parser_ss.str(),
                    val_ss.str()
                });
            }
        }

        // ---------------- Table ----------------
        if (ImGui::BeginTable("PacketTable", 3,
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("Timestamp");
            ImGui::TableSetupColumn("Parsed Packet");
            ImGui::TableSetupColumn("Validation");

            ImGui::TableHeadersRow();

            for (auto& row : rows) {
                ImGui::TableNextRow();

                ImGui::TableNextColumn(); ImGui::Text("%s", row.timestamp.c_str());
                ImGui::TableNextColumn(); ImGui::TextWrapped("%s", row.parsed_output.c_str());
                ImGui::TableNextColumn(); ImGui::TextWrapped("%s", row.validation_output.c_str());
            }

            ImGui::EndTable();
        }

        ImGui::End();

        // Render
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}