# DeepPacket Architecture

DeepPacket is built around a small, modular engine (`dp_engine`) that handles capture, parsing, validation, and serialization. Both the UI and CLI reuse the same engine API.

---

## High-Level Layout

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
```
The engine is compiled into a single static library (`dp_engine`) and linked by:

- the ImGui UI (`app/`)
- the CLI (`cli/`)
- the test suite (`tests/`)

---

## Data Flow

### 1. Capture (Live Mode)

> AF_PACKET socket → capture thread → SPSC Ring Buffer → controller/UI thread → parse/validate → summaries → UI/CLI
- The capture thread blocks on `recvfrom()`
- Raw captured packet bytes are pushed into a lock‑free SPSC queue
- The frontend/controller thread polls the queue, then parses, validates, and stores summaries
- The UI/CLI consumes structured summaries and reconstructs full packet views on demand

### 2. Capture (PCAP Mode)

> PCAP reader → PacketSummary list → UI/CLI
- Packets are read sequentially from a `.pcap` file
- Summaries are generated the same way as live capture
- No capture thread is active

---

## Threading Model

DeepPacket uses a multithreaded producer–consumer pipeline:
```bash
   ┌──────────────────────────┐
   │   Capture Thread         │
   │        (Producer)        │
   └─────────────┬────────────┘
                 │
           recvfrom()
                 │
        raw packet bytes
                 ▼
        ┌──────────────────┐
        │ SPSC Ring Buffer │
        └─────────┬────────┘
                  │
        raw packet bytes
                  ▼
   ┌──────────────────────────┐
   │ Controller / UI Thread   │
   │       (Consumer)         │
   └──────────────────────────┘
                  │
          parse + validate
                  │
                  ▼
        ┌──────────────────┐
        │ Packet Summaries │
        │ retained bytes   │
        └─────────┬────────┘
                  │
                  ▼
              GUI / CLI

```

### **Capture Thread (Producer)**
Created by `CaptureController::start_live_capture()`.

Responsibilities:
- Open raw socket
- Block on `recvfrom()`
- Capture Ethernet frames
- Push raw packet bytes into the SPSC ring buffer

### **UI Thread (Consumer)**
Runs the ImGui event loop or the CLI processing loop.

Responsibilities:
- Poll the ring buffer
- Pop raw packet bytes
- Parse and validate packets
- Create and store packet summaries
- Retain packet bytes when needed for later inspection
- Render or expose summaries to the UI/CLI

This separation prevents the capture thread from being blocked by parsing or
frontend work. The bounded queue absorbs short-term rate differences, while
sustained frontend overload can still cause queue saturation and packet drops.

Capture ownership and mode transitions are serialized separately from packet transfer.
The controller uses lifecycle synchronization when replacing or stopping a capture
source, while summary and statistics access are synchronized independently. The
SPSC queue still requires exactly one producer and one consumer; lifecycle
synchronization does not permit multiple concurrent queue consumers.

Retained packet bytes use shared ownership so a returned packet view remains valid
when controller summaries are cleared. Parsing is zero-copy over the retained
packet buffer, although live packets may be copied once into retained storage.

### Lock‑Free Ring Buffer

DeepPacket implements its own **single‑producer, single‑consumer ring buffer** to avoid:
- mutex contention  
- blocking queues  
- unnecessary copying 
- UI freezes under heavy traffic  

---

## Engine API

The `DeepPacketEngine` class provides a unified interface:

- `start_live_capture(iface)`
- `start_pcap_ingest(path)`
- `stop_capture()`
- `get_summaries_snapshot()`
- `get_packet_view(index)`
- `export_pcap(path)`
- `get_stats()`

Both UI and CLI use this API.

---

## Planned Extensions

- Additional protocol support
- Filter functionality
- Multi-worker parsing and validation pipeline
- Optional Qt‑based UI
