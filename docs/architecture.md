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

> AF_PACKET socket → CaptureController → SPSC Ring Buffer → UI/CLI
- The capture thread blocks on `recvfrom()`
- Raw bytes are wrapped into a `PacketSummary`
- Summaries are pushed into a lock‑free SPSC queue
- The UI/CLI consumes summaries and reconstructs full packet views on demand

### 2. Capture (PCAP Mode)

> PCAP reader → PacketSummary list → UI/CLI
- Packets are read sequentially from a `.pcap` file
- Summaries are generated the same way as live capture
- No capture thread is active

---

## Threading Model

DeepPacket currently runs two primary threads:

   ┌──────────────────────────┐
   │   Capture Thread         │
   │        (Producer)        │
   └─────────────┬────────────┘
                 │
           recvfrom()
                 │
                 ▼
        ┌──────────────────┐
        │  PacketSummary   │
        └─────────┬────────┘
                  │
                  ▼
        ┌──────────────────┐
        │ SPSC Ring Buffer │
        └─────────┬────────┘
                  │
                  ▼
   ┌──────────────────────────┐
   │       UI Thread          │
   │       (Consumer)         │
   └──────────────────────────┘


### **Capture Thread (Producer)**
Created by `CaptureController::start_live_capture()`.

Responsibilities:
- Open raw socket
- Block on `recvfrom()`
- Capture Ethernet frames
- Produce `PacketSummary`
- Push into SPSC ring buffer

### **UI Thread (Consumer)**
Runs the ImGui event loop.

Responsibilities:
- Poll the ring buffer
- Consume summaries
- Update packet list
- Parse + validate selected packet
- Render UI

This separation ensures the UI never stalls under heavy traffic.

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
- Multi‑threaded parsing pipeline
- Optional Qt‑based UI

