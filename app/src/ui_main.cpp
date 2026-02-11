#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include <chrono>
#include <ctime>

#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>

#include "raw-capture.hpp"
#include "parser.hpp"
#include "validation.hpp"
#include "serialization.hpp"


// Forward declarations
void DrawHeaderBar();
void DrawControlBar();
void DrawLeftPane();
void DrawRightPane();
void DrawFooter();
void DrawPacketDetails();
void DrawHexViewer();
static void glfw_error_callback(int error, const char *description);

/*
    ======= GLOBAL =======
*/
struct PacketRow {
    int number;
    float time;
    std::string src;
    std::string dest;
    std::string protocol;
    int length;
    std::string info;
    std::vector<uint8_t> bytes;
    std::vector<std::string> layers;
    std::vector<std::pair<std::string, std::string>> fields; // field name, value pairs
    std::vector<std::string> validationErrors;
};


static int selectedIndex = -1;     // default selected packet index
static bool capturing = false;    // capture state
/*
static std::vector<PacketRow> dummyPackets = {
    {1, 1.180f, "68.114.59.204", "223.241.140.13", "TCP", 71, "17601 → 53 [FIN]", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x11, 0x01} },
    {2, 1.182f, "248.72.207.187", "178.204.127.7", "TCP", 1057, "40708 → 22 [FIN]", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}},

};
*/

static std::vector<PacketRow> packets;

/*
    ======= THEME =======
    - Header Bar:
    - Packet List:
        - Selected Row: Some shade of blue
        - Normal Row: Black with white borders
    - Packet Details Panel:
        - Background: Dark gray
        - Text: White
        - Header bar: Close to black
    - Hex Viewer:
        - Background: Very dark gray
        - Offset Sidebar: Slightly lighter dark gray
        - Hex and ASCII Columns: Black background with white text
*/


/*
    ======= DEEPPACKET HEADER BAR =======
*/

void DrawHeaderBar() {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.05f, 0.05f, 1.0f)); // near-black
    ImGui::BeginChild("HeaderBar", ImVec2(0, 32), true);

    ImGui::PushFont(ImGui::GetFont()); // default font for now

    ImGui::SetCursorPosX(10); //left padding of 10 px
    ImGui::TextColored(ImVec4(1, 1, 1, 1), "DeepPacket");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Network Protocol Analyzer");

    ImGui::PopFont();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}


/*
    ======= CONTROL BAR ========
*/
void DrawControlBar() {
    ImGui::BeginChild("TopBar", ImVec2(0, 48), true);

    // Filter label
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Filter:");
    ImGui::SameLine();

    // Filter input
    static char filterBuf[128] = "";
    ImGui::SetNextItemWidth(250);
    ImGui::InputTextWithHint("##filter", "ip.addr == 192.168.0.1", filterBuf, sizeof(filterBuf));

    // Protocol dropdown
    ImGui::SameLine(0, 20);
    static int protoIndex = 0;
    const char* protos[] = { "All", "TCP", "UDP", "ICMP" };
    ImGui::SetNextItemWidth(100);
    ImGui::Combo("##proto", &protoIndex, protos, IM_ARRAYSIZE(protos));

    // Capture controls (right-aligned)
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 180);

    //static bool capturing = false;
    if (!capturing) {
        if (ImGui::Button("Start Capture", ImVec2(120, 0))) {
            capturing = true;
        }
    } else {
        if (ImGui::Button("Stop", ImVec2(120, 0))) {
            capturing = false;
        }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "LIVE");
    }

    ImGui::EndChild();
}


// RESIZABLE SPLITTER
static float leftWidth = 350.0f;
static float minLeft = 200.0f;
static float maxLeft = 600.0f;


/*
    ======= LEFT PANE =======
    - Contains the Packet List Table
*/
void DrawLeftPane() {
    ImGui::Text("Packet List");
    ImGui::Separator();

    if (ImGui::BeginTable("PacketTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Length");
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < packets.size(); i++) {
            const auto& pkt = packets[i];

            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            if (ImGui::Selectable(std::to_string(pkt.number).c_str(), selectedIndex == i, ImGuiSelectableFlags_SpanAllColumns)) {
                selectedIndex = i;
            }

            ImGui::TableNextColumn(); ImGui::Text("%.3f", pkt.time);
            ImGui::TableNextColumn(); ImGui::Text("%s", pkt.src.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pkt.dest.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pkt.protocol.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%d", pkt.length);
        }

        ImGui::EndTable();
    }
}





void DrawPacketDetails(const PacketRow& pkt) {
    ImGui::Text("Protocol Layers:");
    ImGui::BulletText("Ethernet");
    ImGui::BulletText("IPv4");
    ImGui::BulletText("%s", pkt.protocol.c_str());

    ImGui::Separator();
    ImGui::Text("Fields:");
    ImGui::BulletText("Source IP: %s", pkt.src.c_str());
    ImGui::BulletText("Destination IP: %s", pkt.dest.c_str());
    ImGui::BulletText("Length: %d", pkt.length);

    ImGui::Separator();
    ImGui::TextColored(ImVec4(1, 1, 0, 1), "Validation: Checksum mismatch");
}


// VALIDATION PANEL


// HEX DUMP RENDERER
void DrawHexViewer(const std::vector<uint8_t>& data) {
    const int bytesPerRow = 16;

    ImGui::BeginChild("HexView", ImVec2(0, 0), true);

    // Title bar
    ImGui::Text("Hex Dump");
    ImGui::Separator();

    // -------------------------
    // LEFT OFFSET SIDEBAR
    // -------------------------
    ImGui::BeginChild("OffsetBar", ImVec2(80, ImGui::GetContentRegionAvail().y), true, ImGuiWindowFlags_NoScrollbar);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.25f, 0.25f, 0.25f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

    for (int i = 0; i < (int)data.size(); i += bytesPerRow) {
        ImGui::Text("%08X", i);
    }

    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
    ImGui::EndChild();

    ImGui::SameLine();


    // -------------------------
    // HEX + ASCII TABLE
    // -------------------------
   if (ImGui::BeginTable("HexDumpTable", 2,
    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {

        ImGui::TableSetupColumn("Hex Bytes");
        ImGui::TableSetupColumn("ASCII");

        for (int i = 0; i < (int)data.size(); i += bytesPerRow) {
            ImGui::TableNextRow();

            // HEX COLUMN
            ImGui::TableNextColumn();
            for (int j = 0; j < bytesPerRow; ++j) {
                if (i + j < (int)data.size()) {
                    ImGui::SameLine();
                    ImGui::Text("%02X", data[i + j]);
                } else {
                    ImGui::SameLine();
                    ImGui::Text("  ");
                }
            }

            // ASCII COLUMN
            ImGui::TableNextColumn();
            for (int j = 0; j < bytesPerRow; ++j) {
                if (i + j < (int)data.size()) {
                    uint8_t c = data[i + j];
                    char ch = (c >= 32 && c <= 126) ? (char)c : '.';
                    ImGui::SameLine();
                    ImGui::Text("%c", ch);
                }
            }
        }

        ImGui::EndTable();
    }

    ImGui::EndChild();
}



// RRIGHT PANE
void DrawRightPane() {
    //ImGui::BeginChild("RightPane", ImVec2(0, 0), true);

    ImGui::Text("Packet Details");
    ImGui::Separator();

    if (selectedIndex >= 0) {
        const PacketRow& pkt = packets[selectedIndex];

        ImGui::BeginChild("LayerView", ImVec2(0, ImGui::GetWindowHeight() * 0.4f), true);
        DrawPacketDetails(pkt);
        ImGui::EndChild();

        ImGui::Separator();

        // Hex Viewer
        DrawHexViewer(pkt.bytes);

    } else {
        ImGui::Text("No packet selected.");
    }

   // ImGui::EndChild();
}


// FOOTER
void DrawFooter() {
    ImGui::BeginChild("Footer", ImVec2(0, 20), false);
    ImGui::Text("Packets: %zu | Displayed: %zu", packets.size(), packets.size());
    ImGui::EndChild();
}



// MAIN LOOP
int main() {

    // set up GLFW error callback
    glfwSetErrorCallback(glfw_error_callback);

    // intitialize glfw
    if(!glfwInit()) {
        return 1;
    }

    // Decide GL + GLSL version
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);


    // create window
    GLFWwindow* window = glfwCreateWindow(1200, 720, "ImGui Practice", nullptr, nullptr);
    if(window == nullptr) {
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // enable vsync

    // setup imgui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // setup imgui style
    ImGui::StyleColorsDark();

    // Setup Platform/Renderer Backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);


    // main render loop
    while(!glfwWindowShouldClose(window)) {

        // poll events
        glfwPollEvents();

        // start imgui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // UI stuff
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Root", nullptr,
            ImGuiWindowFlags_NoDecoration |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_NoBringToFrontOnFocus
        );

        DrawHeaderBar();
        DrawControlBar();

        // --- CAPTURE PIPELINE ---
        static SocketCapture capture;
        //static bool capturing = false;
        static std::vector<uint8_t> buffer(65536);


        if (capturing && capture.valid()) {
            ssize_t bytes = capture.read_frame(buffer.data(), buffer.size());

            if (bytes > 0) {
                ParsedPacket pkt = parse_packet(std::span<const uint8_t>(buffer.data(), bytes));
                PacketValidator validator(pkt.view);

                nlohmann::json j = packet_to_json(pkt.view, validator);

                PacketRow row;
                row.number = packets.size() + 1;
                row.time = ImGui::GetTime();

                // Extract json fields for the gui display
                if (j.contains("layers") && j["layers"].contains("ipv4")) {
                    row.src = j["layers"]["ipv4"]["src_ip"];
                    row.dest = j["layers"]["ipv4"]["dst_ip"];
                } else {
                    row.src = "N/A";
                    row.dest = "N/A";
                }

                row.protocol = j["summary"]["protocol"];
                row.length = j["summary"]["length"];
                row.info = j["summary"]["validation_status"];
                row.bytes = j["raw"]["bytes"].get<std::vector<uint8_t>>();

                packets.push_back(row);
            }
        }



        ImGui::BeginChild("MainArea", ImVec2(0, -20), false);
        // LEFT PANE
        ImGui::BeginChild("LeftPane", ImVec2(leftWidth, 0), true);
        DrawLeftPane();
        ImGui::EndChild();

        // SPLITTER
        ImGui::SameLine();
        ImGui::InvisibleButton("##splitter", ImVec2(4.0f, ImGui::GetContentRegionAvail().y));
        if (ImGui::IsItemActive()) {
            leftWidth += ImGui::GetIO().MouseDelta.x;
            if (leftWidth < minLeft) {
                leftWidth = minLeft;
            }
            if (leftWidth > maxLeft) {
                leftWidth = maxLeft;
            }
        }

        // RIGHT PANE
        ImGui::SameLine();
        ImGui::BeginChild("RightPane", ImVec2(0, 0), true);
        DrawRightPane();
        ImGui::EndChild();

        ImGui::EndChild();

        DrawFooter();


        ImGui::End();


        // Rendering
        ImGui::Render();
        int display_width, display_height;
        glfwGetFramebufferSize(window, &display_width, &display_height);
        glViewport( 0, 0, display_width, display_height);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}


// ERROR CALLBACKS
static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}



