# DeepPacket Design Notes

DeepPacket is intentionally small and minimal. The goal is not to compete with Wireshark, but to provide a clear, readable implementation of packet capture and parsing.

---

## Why No libpcap?

libpcap abstracts away:
- socket setup
- buffering
- filtering
- timestamping
- device configuration

DeepPacket avoids these abstractions to expose the raw mechanics of packet capture.  
Using Linux AF_PACKET sockets makes the capture path explicit and easy to understand/modify.

---

## Why Zero‑Copy Parsing?

Most protocol libraries allocate new buffers or copy header structures.  
DeepPacket instead parses directly from the raw byte buffer using pointer offsets.

Benefits:
- Avoids memcpy during parsing
- Significantly improves latency especially when dealing with large bursts of packets.

---

## Why Manual Protocol Parsers?

DeepPacket implements Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMPv4, and ICMPv6 by hand.

Reasons:
- educational clarity  
- full control over validation  
- no dependency bloat  
- easier debugging  
- easier experimentation with malformed packets  

---

## Why a Custom Ring Buffer?

A lock‑free SPSC queue is ideal for:
- one producer (capture thread)
- one consumer (UI thread)

It avoids:
- mutex contention  
- UI freezes.

---

## Why ImGui?

ImGui is:
- lightweight  
- easy to integrate  
- perfect for real‑time packet lists  
- Quicker to prototype too since GUI was like an add on.

---

## Core Design Philosophy

DeepPacket is built around three principles:

### 1. **Clarity**
The code should be readable and understandable without digging through thousands of lines.

### 2. **Control**
Every byte of every packet is parsed manually. No hidden abstractions.

### 3. **Modularity**
The core backend is independent of the UI and CLI.  
Everything is composable.
The modular nature of the engine also makes it easy to integrate/experiment with adding more protocols/validation rules etc.
