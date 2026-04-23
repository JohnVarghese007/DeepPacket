# DeepPacket

A zero-copy network packet inspection tool with live capture, protocol parsing, validation, and a lightweight Wireshark-style UI.

> **Status:** v1 close to completion

---

## Overview

DeepPacket is a lightweight packet analysis tool inspired by Wireshark.
It captures raw Ethernet frames from a Linux network interface, parses protocol layers, validates fields against RFC rules, and displays results in a custom ImGui-based UI.

The project explores systems-level engineering concepts including:

* Raw socket capture
* Zero-copy binary parsing
* RFC-aware validation
* Real-time UI rendering
* PCAP ingestion and export

DeepPacket aims to replicate a small, educational subset of Wireshark’s functionality while maintaining a clean, modular architecture. The modular architecture of the parser and validation layers allow seamless integration of more protocols in addition to the ones natively supported.

Another point of focus was stability. DeepPacket is built with minimal external dependencies.  
It does not use libpcap or third‑party protocol parsers — all capture, parsing, validation, and serialization logic is implemented manually.  
Only lightweight UI/runtime libraries (ImGui, ImGuiFileDialog, GLFW) are used.

---

## Current Features

### Capture & PCAP

* Live packet capture using Linux raw sockets
* PCAP file ingestion (offline analysis mode)
* PCAP export (validated in Wireshark)
* Automatic mode switching (Live ↔ PCAP)

### Protocol Support

Zero-copy parsing + validation for:

* Ethernet II
* IPv4
* ARP
* TCP
* UDP
* ICMP

### UI (ImGui-based for now)

* Real-time packet list with timestamps, IPs, protocol, and length
* Packet details panel with:

  * Summary fields
  * Layer breakdown (Ethernet/IP/TCP/UDP/ICMP)
  * Validation results
* Hex viewer with offset, hex, and ASCII columns
* Resizable split panes
* Load/Export PCAP buttons
* Start/Stop live capture
* Interface selection
* Filter input (UI only for now, functionality yet to be implemented)

### Validation

* Field-level validation for supported protocols
* Error reporting per packet
* RFC-aware checksum and header checks

### Testing

* Extensive test suite covering:

  * Parsing
  * Validation
  * Serialization
  * PCAP read/write

---

## Parallelization & Architecture

DeepPacket uses a lightweight, high‑performance multithreaded architecture designed for real‑time packet capture without UI stalls.

### Thread Model

DeepPacket currently runs two primary threads:

**1. Capture Thread (Producer)**  
Created by `CaptureController::start_live_capture()`.  
This thread:
- Opens the raw socket  
- Blocks on `recvfrom()`  
- Captures raw Ethernet frames  
- Produces `PacketSummary` objects  
- Pushes them into a custom lock‑free SPSC ring buffer  

**2. UI Thread (Consumer)**  
The main thread running the ImGui event loop.  
This thread:
- Polls the ring buffer  
- Consumes packet summaries  
- Updates the packet list  
- Performs full parsing + validation when a packet is selected  
- Renders the UI  

### Lock‑Free Ring Buffer

DeepPacket implements its own **single‑producer, single‑consumer ring buffer** to avoid:

- mutex contention  
- blocking queues  
- unnecessary memory copies  
- UI freezes under heavy traffic  

This design ensures:
- real‑time packet ingestion  
- smooth UI rendering  
- predictable performance  
- minimal latency between capture and display  

### Why This Matters

Unlike tools that rely on libpcap or heavy middleware, DeepPacket’s capture → queue → UI pipeline is built entirely from scratch.  
This provides full control over performance characteristics and makes the project a genuine systems‑engineering effort rather than a wrapper around existing libraries.

---

## Planned Features

* IPv6 parsing + validation
* Additional pipeline parallelization.
* UI performance improvements
* Optional migration to Qt-based UI 
* Additional protocol support
* Filter engine (BPF-like or custom)
* CLI tool for headless analysis

---

## Build Instructions

DeepPacket uses **CMake**.

### 1. Configure & Build

From the project root:

```bash
./build.sh
```

### 2. Executables

The build produces:

* `DeepPacketTests` — test suite
* `DeepPacketUI` — graphical packet analyzer

### 3. Run Tests

```bash
sudo ./build/tests/DeepPacketTests > output.txt
```

### 4. Run the UI

```bash
sudo ./build/app/DeepPacketUI
```

> Root privileges are required for raw socket capture.

---

## Screenshot

![DeepPacket Screenshot](./media/image.png)

*(Replace `screenshot.png` with your actual screenshot filename.)*

---

## Third-Party Libraries

DeepPacket vendors a small set of open-source libraries:

* [Dear ImGui](https://github.com/ocornut/imgui) — Immediate-mode GUI framework (MIT)
* [ImGuiFileDialog](https://github.com/aiekick/ImGuiFileDialog) — File dialog widget for ImGui (MIT)
* [GLFW](https://github.com/glfw/glfw) — Windowing + input backend (zlib/libpng)

All licenses for these libraries are included in the `third_party/` directory.

---

## Notes

* DeepPacket is still under active development and may be worked on every now and then.
* Some UI elements (e.g., filter box) are placeholders for future features.
* Interface auto-detection is implemented, but fallback defaults to default value of `enp0s3` if unavailable.
