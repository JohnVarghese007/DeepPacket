#include "imgui.h"
#include "ImGuiFileDialog.h"
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
#include <optional>
#include <algorithm>
#include <cstdio>
#include <arpa/inet.h>

#include "raw-capture.hpp"
#include "parser.hpp"
#include "validation.hpp"
#include "serialization.hpp"
#include "capture_controller.hpp"


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

static CaptureController controller;
static int selectedIndex = -1;     // default selected packet index
static bool capturing = false;    // capture state
static std::vector<std::string> interfaceOptions;
static int selectedInterfaceIndex = 0;
static int cachedDetailIndex = -1;
static std::vector<uint8_t> cachedDetailBytes;
static std::optional<ParsedPacket> cachedDetailPacket;
static std::optional<PacketValidator> cachedDetailValidator;

static const char* ProtocolToString(TransportProtocol protocol) {
    switch (protocol) {
        case TransportProtocol::TCP:  return "TCP";
        case TransportProtocol::UDP:  return "UDP";
        case TransportProtocol::ICMP: return "ICMP";
        case TransportProtocol::ARP:  return "ARP";
        default:                      return "UNKNOWN";
    }
}

static const char* ValidationToString(ValidationStatus status) {
    switch (status) {
        case ValidationStatus::OK:    return "OK";
        case ValidationStatus::ERROR: return "ERROR";
        default:                      return "UNKNOWN";
    }
}

static std::string MacToString(const uint8_t mac[6]) {
    char buf[18] = {};
    std::snprintf(
        buf,
        sizeof(buf),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    return std::string(buf);
}

static std::string IPv4ToString(uint32_t addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}
/*
static std::vector<PacketRow> dummyPackets = {
    {1, 1.180f, "68.114.59.204", "223.241.140.13", "TCP", 71, "17601 → 53 [FIN]", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x11, 0x01} },
    {2, 1.182f, "248.72.207.187", "178.204.127.7", "TCP", 1057, "40708 → 22 [FIN]", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}},

};
*/

//static std::vector<PacketRow> packets;

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

    // Interface dropdown
    ImGui::SameLine(0, 12);
    ImGui::Text("Interface:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);

    if (!interfaceOptions.empty()) {
        if (selectedInterfaceIndex < 0 || selectedInterfaceIndex >= (int)interfaceOptions.size()) {
            selectedInterfaceIndex = 0;
        }

        std::vector<const char*> iface_labels;
        iface_labels.reserve(interfaceOptions.size());
        for (const auto& iface : interfaceOptions) {
            iface_labels.push_back(iface.c_str());
        }

        ImGui::Combo("##iface", &selectedInterfaceIndex, iface_labels.data(),
                     (int)iface_labels.size());
    } else {
        ImGui::BeginDisabled();
        const char* none[] = { "N/A" };
        int dummy = 0;
        ImGui::Combo("##iface", &dummy, none, 1);
        ImGui::EndDisabled();
    }

    //
    // PCAP Controls (LEFT SIDE)
    //
    ImGui::SameLine(0, 20);

    if (ImGui::Button("Load PCAP", ImVec2(120, 0))) {
        IGFD::FileDialogConfig config;
        config.path = ".";
        ImGuiFileDialog::Instance()->OpenDialog(
            "OpenPCAP", "Open PCAP File", ".pcap", config
        );
    }

    ImGui::SameLine();

    if (ImGui::Button("Export PCAP", ImVec2(120, 0))) {
        IGFD::FileDialogConfig config;
        config.path = ".";
        ImGuiFileDialog::Instance()->OpenDialog(
            "SavePCAP", "Save PCAP File", ".pcap", config
        );
    }

    //
    // NOW push Start/Stop to the right
    //
    float rightAlignX = ImGui::GetWindowWidth() - 180;
    ImGui::SameLine();
    ImGui::SetCursorPosX(rightAlignX);

    //
    // Capture controls
    //
    if (controller.mode() == CaptureMode::PCAP) {
        ImGui::BeginDisabled();
        ImGui::Button("Start Capture", ImVec2(120, 0));
        ImGui::SameLine();
        ImGui::Button("Stop", ImVec2(120, 0));
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 0.8f, 0, 1), "PCAP MODE");
    }
    else {
        if (!capturing) {
            if (ImGui::Button("Start Capture", ImVec2(120, 0))) {
                const std::string selected_interface =
                    (!interfaceOptions.empty() &&
                     selectedInterfaceIndex >= 0 &&
                     selectedInterfaceIndex < (int)interfaceOptions.size())
                        ? interfaceOptions[selectedInterfaceIndex]
                        : "enp0s3";

                capturing = controller.start_live_capture(selected_interface);
            }
        } else {
            if (ImGui::Button("Stop", ImVec2(120, 0))) {
                capturing = false;
                controller.stop_capture();
            }
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "LIVE");
        }
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

    const auto& summaries = controller.get_summaries_snapshot();
    static std::vector<std::string> row_no_cache;
    static std::vector<std::string> row_time_cache;
    static std::vector<std::string> row_proto_cache;

    if (row_no_cache.size() > summaries.size()) {
        row_no_cache.resize(summaries.size());
        row_time_cache.resize(summaries.size());
        row_proto_cache.resize(summaries.size());
    }

    if (row_no_cache.size() < summaries.size()) {
        const std::size_t old_size = row_no_cache.size();
        row_no_cache.resize(summaries.size());
        row_time_cache.resize(summaries.size());
        row_proto_cache.resize(summaries.size());

        for (std::size_t i = old_size; i < summaries.size(); ++i) {
            const auto& s = summaries[i];
            row_no_cache[i] = std::to_string(i + 1);
            row_proto_cache[i] = ProtocolToString(s.protocol);

            const double time_seconds = static_cast<double>(s.timestamp.count()) / 1'000'000.0;
            char time_buf[32] = {};
            std::snprintf(time_buf, sizeof(time_buf), "%.3f", time_seconds);
            row_time_cache[i] = time_buf;
        }
    }
    
    if (ImGui::BeginTable("PacketTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Length");
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(summaries.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const std::size_t i = static_cast<std::size_t>(row);
                const auto& s = summaries[i];

                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                const bool is_selected = (selectedIndex >= 0) && (selectedIndex == row);
                if (ImGui::Selectable(row_no_cache[i].c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    selectedIndex = row;
                }

                ImGui::TableNextColumn(); ImGui::TextUnformatted(row_time_cache[i].c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.src_ip.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.dst_ip.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(row_proto_cache[i].c_str());
                ImGui::TableNextColumn(); ImGui::Text("%u", s.length);
            }
        }

        ImGui::EndTable();
    }
}





void DrawPacketDetails(const ParsedPacket& pkt, const PacketValidator& validator) {
    ImGui::Text("Protocol Layers:");
    ImGui::Separator();

    // Ethernet
    if (pkt.view.has_eth) {
        ImGui::Text("Ethernet");
        ImGui::Indent();
        ImGui::Text("Src MAC: %s", MacToString(pkt.view.eth_layer.eth->src_mac).c_str());
        ImGui::Text("Dst MAC: %s", MacToString(pkt.view.eth_layer.eth->dest_mac).c_str());
        ImGui::Text("Type: 0x%04X", ntohs(pkt.view.eth_layer.eth->ether_type));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // IPv4
    if (pkt.view.has_ip) {
        ImGui::Text("IPv4");
        ImGui::Indent();
        ImGui::Text("Src IP: %s", IPv4ToString(pkt.view.ip_layer.iph->src_addr).c_str());
        ImGui::Text("Dst IP: %s", IPv4ToString(pkt.view.ip_layer.iph->dest_addr).c_str());
        ImGui::Text("TTL: %u", pkt.view.ip_layer.iph->ttl);
        ImGui::Text("Protocol: %u", pkt.view.ip_layer.iph->protocol);
        ImGui::Text("Header Checksum: 0x%04X", ntohs(pkt.view.ip_layer.iph->header_checksum));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // TCP
    if (pkt.view.has_tcp) {
        ImGui::Text("TCP");
        ImGui::Indent();
        ImGui::Text("Src Port: %u", ntohs(pkt.view.tcp_layer.tcph->src_port));
        ImGui::Text("Dst Port: %u", ntohs(pkt.view.tcp_layer.tcph->dest_port));
        ImGui::Text("Seq: %u", ntohl(pkt.view.tcp_layer.tcph->seq_num));
        ImGui::Text("Ack: %u", ntohl(pkt.view.tcp_layer.tcph->ack_num));
        ImGui::Text("Flags: 0x%02X", pkt.view.tcp_layer.tcph->flags);
        ImGui::Unindent();
        ImGui::Separator();
    }

    // UDP
    if (pkt.view.has_udp) {
        ImGui::Text("UDP");
        ImGui::Indent();
        ImGui::Text("Src Port: %u", ntohs(pkt.view.udp_layer.udph->src));
        ImGui::Text("Dst Port: %u", ntohs(pkt.view.udp_layer.udph->dest));
        ImGui::Text("Length: %u", ntohs(pkt.view.udp_layer.udph->length));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // ICMP
    if (pkt.view.has_icmp) {
        ImGui::Text("ICMP");
        ImGui::Indent();
        ImGui::Text("Type: %u", pkt.view.icmp_layer.icmph->type);
        ImGui::Text("Code: %u", pkt.view.icmp_layer.icmph->code);
        ImGui::Unindent();
        ImGui::Separator();
    }

    // Validation
    ImGui::Text("Validation:");
    ImGui::Indent();
    for (auto err : validator.errors) {
        if (err != ValidationError::NONE) {
            ImGui::TextColored(ImVec4(1, 0.2f, 0.2f, 1), "%s", to_string(err).c_str());
        }
    }
    ImGui::Unindent();
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
    ImGui::Text("Packet Details");
    ImGui::Separator();

    if (selectedIndex < 0) {
        ImGui::Text("No packet selected.");
        return;
    }

    // --- Retrieve summaries + raw bytes ---
    const auto& summaries = controller.get_summaries_snapshot();
    if (selectedIndex >= (int)summaries.size()) {
        ImGui::Text("Invalid selection.");
        return;
    }

    const PacketSummary& summary = summaries[selectedIndex];

    // --- TOP: Summary fields from PacketSummary ---
    ImGui::BeginChild("SummaryFields", ImVec2(0, ImGui::GetWindowHeight() * 0.28f), true);

    ImGui::Text("Summary Fields");
    ImGui::Separator();

    const double ts_seconds = static_cast<double>(summary.timestamp.count()) / 1'000'000.0;
    ImGui::Text("Timestamp: %.6f s", ts_seconds);
    ImGui::Text("Source IP: %s", summary.src_ip.c_str());
    ImGui::Text("Destination IP: %s", summary.dst_ip.c_str());
    ImGui::Text("Source Port: %u", summary.src_port);
    ImGui::Text("Destination Port: %u", summary.dst_port);
    ImGui::Text("Protocol: %s", ProtocolToString(summary.protocol));
    ImGui::Text("Length: %u", summary.length);
    ImGui::Text("Validation: %s", ValidationToString(summary.validation));
    ImGui::Text("TCP Flags: 0x%02X", summary.tcp_flags);

    ImGui::EndChild();

    ImGui::Separator();

    // Get raw bytes for this packet
    PacketView view = controller.get_packet_view(selectedIndex);
    if (view.data == nullptr || view.size() == 0) {
        cachedDetailIndex = -1;
        cachedDetailBytes.clear();
        cachedDetailPacket.reset();
        cachedDetailValidator.reset();
        ImGui::Text("Packet data unavailable.");
        return;
    }

    // --- Re-parse + validate only when selection changes ---
    if (cachedDetailIndex != selectedIndex || !cachedDetailPacket.has_value() || !cachedDetailValidator.has_value()) {
        cachedDetailBytes.assign(view.data, view.data + view.size());
        cachedDetailPacket.emplace(parse_packet(std::span<const uint8_t>(cachedDetailBytes.data(), cachedDetailBytes.size())));
        cachedDetailValidator.emplace(cachedDetailPacket->view);
        cachedDetailIndex = selectedIndex;
    }

    const ParsedPacket& pkt = *cachedDetailPacket;
    const PacketValidator& validator = *cachedDetailValidator;

    // --- TOP: Layer + Field Breakdown ---
    ImGui::BeginChild("LayerView", ImVec2(0, ImGui::GetWindowHeight() * 0.34f), true);

    ImGui::Text("Layers");
    ImGui::Separator();

    // Ethernet
    if (pkt.view.has_eth) {
        ImGui::Text("Ethernet");
        ImGui::Indent();
        ImGui::Text("Src MAC: %s", MacToString(pkt.view.eth_layer.eth->src_mac).c_str());
        ImGui::Text("Dst MAC: %s", MacToString(pkt.view.eth_layer.eth->dest_mac).c_str());
        ImGui::Text("Ethertype: 0x%04X", ntohs(pkt.view.eth_layer.eth->ether_type));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // IPv4
    if (pkt.view.has_ip) {
        ImGui::Text("IPv4");
        ImGui::Indent();
        ImGui::Text("Src IP: %s", IPv4ToString(pkt.view.ip_layer.iph->src_addr).c_str());
        ImGui::Text("Dst IP: %s", IPv4ToString(pkt.view.ip_layer.iph->dest_addr).c_str());
        ImGui::Text("TTL: %u", pkt.view.ip_layer.iph->ttl);
        ImGui::Text("Protocol: %u", pkt.view.ip_layer.iph->protocol);
        ImGui::Text("Header Checksum: 0x%04X", ntohs(pkt.view.ip_layer.iph->header_checksum));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // TCP
    if (pkt.view.has_tcp) {
        ImGui::Text("TCP");
        ImGui::Indent();
        ImGui::Text("Src Port: %u", ntohs(pkt.view.tcp_layer.tcph->src_port));
        ImGui::Text("Dst Port: %u", ntohs(pkt.view.tcp_layer.tcph->dest_port));
        ImGui::Text("Seq: %u", ntohl(pkt.view.tcp_layer.tcph->seq_num));
        ImGui::Text("Ack: %u", ntohl(pkt.view.tcp_layer.tcph->ack_num));
        ImGui::Text("Flags: 0x%02X", pkt.view.tcp_layer.tcph->flags);
        ImGui::Unindent();
        ImGui::Separator();
    }

    // UDP
    if (pkt.view.has_udp) {
        ImGui::Text("UDP");
        ImGui::Indent();
        ImGui::Text("Src Port: %u", ntohs(pkt.view.udp_layer.udph->src));
        ImGui::Text("Dst Port: %u", ntohs(pkt.view.udp_layer.udph->dest));
        ImGui::Text("Length: %u", ntohs(pkt.view.udp_layer.udph->length));
        ImGui::Unindent();
        ImGui::Separator();
    }

    // ICMP
    if (pkt.view.has_icmp) {
        ImGui::Text("ICMP");
        ImGui::Indent();
        ImGui::Text("Type: %u", pkt.view.icmp_layer.icmph->type);
        ImGui::Text("Code: %u", pkt.view.icmp_layer.icmph->code);
        ImGui::Unindent();
        ImGui::Separator();
    }

    // Validation
    ImGui::Text("Validation");
    ImGui::Indent();
    bool ok = true;
    for (auto err : validator.errors) {
        if (err != ValidationError::NONE) {
            ok = false;
            ImGui::TextColored(ImVec4(1, 0.2f, 0.2f, 1), "%s", to_string(err).c_str());
        }
    }
    if (ok) {
        ImGui::TextColored(ImVec4(0.2f, 1, 0.2f, 1), "OK");
    }
    ImGui::Unindent();

    ImGui::EndChild();

    ImGui::Separator();

    // --- BOTTOM: Hex Viewer ---
    DrawHexViewer(cachedDetailBytes);
}



// FOOTER
void DrawFooter() {
    ImGui::BeginChild("Footer", ImVec2(0, 20), false);
    const auto& summaries = controller.get_summaries_snapshot();
    const CaptureStats stats = controller.get_stats();
    ImGui::Text(
        "Packets: %zu | Displayed: %zu | Captured: %llu | Dropped: %llu",
        summaries.size(),
        summaries.size(),
        static_cast<unsigned long long>(stats.packets_captured),
        static_cast<unsigned long long>(stats.packets_dropped)
    );
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
    GLFWwindow* window = glfwCreateWindow(1200, 720, "DeepPacket", nullptr, nullptr);
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

    interfaceOptions = controller.list_interfaces();
    if (interfaceOptions.empty()) {
        interfaceOptions.push_back("enp0s3");
        selectedInterfaceIndex = 0;
    } else {
        auto it = std::find(interfaceOptions.begin(), interfaceOptions.end(), "enp0s3");
        if (it != interfaceOptions.end()) {
            selectedInterfaceIndex = static_cast<int>(std::distance(interfaceOptions.begin(), it));
        } else {
            selectedInterfaceIndex = 0;
        }
    }

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
        
        // Handle Open PCAP dialog
        if (ImGuiFileDialog::Instance()->Display("OpenPCAP")) {
            if (ImGuiFileDialog::Instance()->IsOk()) {
                std::string path = ImGuiFileDialog::Instance()->GetFilePathName();
                controller.start_pcap_ingest(path);
                capturing = false;
                selectedIndex = -1;
            }
            ImGuiFileDialog::Instance()->Close();
        }

        // Handle Save PCAP dialog
        if (ImGuiFileDialog::Instance()->Display("SavePCAP")) {
            if (ImGuiFileDialog::Instance()->IsOk()) {
                std::string path = ImGuiFileDialog::Instance()->GetFilePathName();
                controller.export_pcap(path);
            }
            ImGuiFileDialog::Instance()->Close();
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



