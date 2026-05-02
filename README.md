# DeepPacket

A zero-copy network packet inspection tool with live capture, protocol parsing, validation, and a lightweight Wireshark-style UI as well as a command-line interface.

> **Status:** v1 complete
> (Python bindings planned)

---

## Overview

DeepPacket is a lightweight packet analysis tool inspired by Wireshark.
It captures raw Ethernet frames from a Linux network interface, parses protocol layers, validates fields against RFC rules, and displays results through either a custom ImGui-based UI or a headless command-line interface (dpctl).

DeepPacket is built with **no libpcap** and **no third‑party protocol parsers** — all capture, parsing, validation, and serialization logic is implemented manually.
Only lightweight UI libraries (Dear ImGui and ImGuiFileDialog) are vendored; platform components such as GLFW and OpenGL are used as **system dependencies**.

The goal is to make packet capture and protocol parsing easy to understand, modify, and experiment with, without the complexity of Wireshark’s codebase.

---

## Project Structure

DeepPacket is organized around a unified engine namespace (dp/), with each subsystem implemented as a modular component and compiled into a single static library (dp_engine).

```bash
DeepPacket/
├── dp/                  # Core engine (dp_engine)
│   ├── engine/          # Unified DeepPacket API
│   ├── core/            # High-level orchestration (capture control, summaries)
│   ├── capture/         # Raw socket capture (linux only for now) + ring buffer
│   ├── parser/          # Zero-copy protocol parsing
│   ├── validation/      # RFC-aware validation logic
│   ├── serialization/   # Export/load functionality
│   └── pcap/            # PCAP reader/writer
│
├── app/                 # ImGui-based UI application
├── tests/               # Unit and integration tests
├── cli/                 # dpctl cli
├── docs/                # documentation
├── third_party/         # Vendored dependencies (ImGui, ImGuiFileDialog)
└── build/               # Build output (generated)
```

All modules under dp/ share a consistent namespace (dp::<module>) and are designed to be composable, allowing the UI, CLI and test suite to reuse the same packet processing pipeline.

---

## Current Features

### Capture

* Live packet capture using Linux raw sockets
* PCAP file ingestion + export

### Protocol Support

Zero-copy parsing + validation for:

* Ethernet II
* IPv4
* IPv6 (minimal)
* ICMPv4
* ICMPv6
* ARP
* TCP
* UDP

### UI (ImGui-based for now)

* Real-time packet list with timestamps, IPs, protocol, and length
* Packet details panel with layer breakdown and validation
* Hex viewer 
* Interface selection
* Live capture
* PCAP import/export integration
* Filter box (UI only, not implemented yet)

### CLI (dpctl)

* Non‑blocking REPL for live capture and PCAP analysis
* Real‑time packet output stream

### Validation

* Field-level validation for supported protocols
* RFC‑aware header and checksum checks  
* Error reporting per packet

### Testing

* Extensive test suite covering 50+ supported validation errors for malformed packets.
* For full testing reference `docs/validation.md`

---

## Documentation

DeepPacket includes additional documentation for developers and contributors:
- **Architecture** — engine layout, module responsibilities, data flow, threading model etc.  
  - `docs/architecture.md`
- **Design Notes** — goals, constraints, and rationale behind major decisions  
  - `docs/design.md`
- **CLI Reference** — full command list and examples  
  - `docs/cli.md`
- **Protocol Notes** — parsing logic and validation rules  
  - `docs/validation.md`

---

## Why DeepPacket ?

DeepPacket exists for one reason: to show how packet capture and protocol parsing actually work under the hood.

Most analyzers rely on libpcap and large protocol libraries. DeepPacket avoids those layers entirely — it captures packets directly with Linux raw sockets and parses every supported protocol by hand. The result is a small, readable codebase that’s easy to study, extend, and experiment with.

If you want to understand packet formats, write custom protocol logic, or explore low‑level networking without the complexity of Wireshark’s codebase, DeepPacket gives you a clean starting point.

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

* `deeppacket-tests` — test suite
* `deeppacket` — graphical packet analyzer
* `dpctl` — command-line packet analyzer

### 3. Run Tests

```bash
sudo ./build/tests/deeppacket-tests > output.txt
```

### 4. Run the UI

```bash
sudo ./build/app/deeppacket
```

### 5. Run the CLI

```bash
sudo ./build/cli/dpctl
```

> Root privileges are required for raw socket capture.

---

## Screenshot

![DeepPacket Screenshot](./media/image.png)


---

## Third-Party Libraries

DeepPacket vendors a small set of lightweight UI libraries:

* [Dear ImGui](https://github.com/ocornut/imgui) — Immediate‑mode GUI framework (MIT)
* [ImGuiFileDialog](https://github.com/aiekick/ImGuiFileDialog) — File dialog widget for ImGui (MIT)

These libraries are included directly in the `third_party/` directory.

DeepPacket also relies on the following **system-provided** dependencies:

* **GLFW** — Windowing + input backend (zlib/libpng), installed via system package manager  
* **OpenGL** — Provided by the system’s graphics drivers (Mesa/NVIDIA/AMD)

Only the vendored libraries are stored in the repository; system dependencies must be installed separately.

---

## License

DeepPacket © 2026 John Varghese — All Rights Reserved
Licensed under Creative Commons Attribution‑NonCommercial‑NoDerivatives 4.0 International  
(CC BY‑NC‑ND 4.0)

This license allows others to view and share the project with attribution,
but prohibits commercial use, modification, or redistribution of derivative works.

Full license text:
https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode

---

## Notes

* DeepPacket is still under active development and may be worked on every now and then.
* Some UI elements (e.g., filter box) are placeholders for future features.
* Interface auto-detection is implemented, but fallback defaults to default value of `enp0s3` if unavailable.
