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

---

## Planned Features / Ideas for features

* IPv6 parsing + validation
* Additional pipeline parallelization.
* UI performance improvements
* Optional migration to Qt-based UI 
* Additional protocol support
* Filter engine (BPF-like or custom)
* CLI enhancements
