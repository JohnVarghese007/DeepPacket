🧠 DeepPacket 2-Month Roadmap (Systems-First)
PHASE 0 — Baseline (2–3 days)

Goal: Make sure your C/C++ & Linux fundamentals won’t slow you down.

Learn

C vs C++ memory model

Stack vs heap

malloc/free vs new/delete

Struct layout, padding, alignment

Endianness (VERY important)

Resources

📘 Computer Systems: A Programmer’s Perspective (CS:APP)
Chapters 2 (Data Representation), 3.7 (Memory Layout)

📺 Jacob Sorber – Memory Layout in C (YouTube)

Mini Checkpoints

Print byte-level representation of uint32_t on your machine

Write a program that:

casts a byte buffer to a struct

detects little vs big endian

PHASE 1 — Networking Fundamentals (Week 1)

Goal: You must understand packets conceptually before touching raw sockets.

Learn

OSI vs TCP/IP model

Ethernet frames

IP (IPv4 header fields)

TCP vs UDP (flags, sequence numbers)

MTU, fragmentation

Resources

📘 Computer Networking: A Top-Down Approach (Kurose & Ross)

Chapters 1, 3

📺 “TCP/IP Illustrated” lectures (search: TCP/IP Illustrated Wireshark)

🧪 Wireshark (install now)

Mini Checkpoints

Capture traffic in Wireshark:

HTTP request

DNS query

Manually identify:

Ethernet header

IP header

TCP header fields

If you can’t point to fields in Wireshark → don’t proceed yet.

PHASE 2 — Linux Networking & Sockets (Week 2)

Goal: Be fluent with sockets before going raw.

Learn

socket(), bind(), recv(), send()

AF_INET, AF_PACKET

Blocking vs non-blocking I/O

select, poll, epoll

Resources

📘 UNIX Network Programming, Vol 1 — Stevens
Chapters 1–6

📺 Jacob Sorber – Sockets in C series

Mini Checkpoints

Write a TCP echo server in C

Write a UDP packet receiver

Implement select()-based multi-client server

PHASE 3 — Raw Sockets & Packet Capture (Week 3)

Goal: This is where DeepPacket truly begins.

Learn

Raw sockets (SOCK_RAW)

Privileges & capabilities

AF_PACKET on Linux

Promiscuous mode

struct ethhdr, iphdr, tcphdr

Resources

📘 Linux Network Programming – chapter on raw sockets

📄 Linux man pages:

packet(7)

raw(7)

📺 “Raw Socket Programming in C (Linux)”

Mini Checkpoints

Capture raw Ethernet frames

Print:

MAC src/dst

EtherType

Filter only IPv4 packets

At this point you’ve crossed into systems territory.

PHASE 4 — Manual Protocol Parsing (Week 4)

Goal: Decode packets without libraries.

Learn

Header parsing

Bit fields

Checksums

TCP flags

Network byte order (ntohs, ntohl)

Resources

📘 TCP/IP Illustrated Vol 1 — Stevens (gold standard)

📺 LiveOverflow — Network Packet Analysis

Mini Checkpoints

Parse IPv4 header manually

Parse TCP header:

flags

seq/ack numbers

Detect:

SYN

FIN

RST packets

PHASE 5 — Session Tracking & State (Week 5)

Goal: Your sniffer becomes intelligent, not just a logger.

Learn

5-tuple flow identification

TCP connection state machine

Hash tables for sessions

Timeouts & cleanup

Resources

📘 Computer Networks – Tanenbaum (TCP state)

📄 RFC 793 (skim only)

Mini Checkpoints

Track TCP connections:

NEW

ESTABLISHED

CLOSED

Print per-connection stats:

bytes sent

duration

This is already resume-worthy.

PHASE 6 — Performance & Concurrency (Week 6)

Goal: Handle real traffic without dying.

Learn

Threads vs event loops

Lock-free queues (basic idea)

Zero-copy (recvmsg, mmap)

Ring buffers

Resources

📘 Linux Performance Tools – Brendan Gregg

📺 “epoll explained” (Jacob Sorber)

Mini Checkpoints

Packet capture thread → analysis thread

Measure packet rate (pps)

Avoid malloc in hot paths

PHASE 7 — Output, Storage & Tooling (Week 7)

Goal: Make it useful.

Learn

PCAP format

Logging strategies

Binary file formats

CLI argument parsing

Resources

📄 PCAP file format spec

📺 Writing a PCAP writer in C

Mini Checkpoints

Save captured packets to .pcap

Open output in Wireshark

Add CLI flags:

interface

protocol filter

PHASE 8 — Polishing DeepPacket (Week 8)

Goal: Turn it into a serious systems project.

Optional Enhancements

Custom protocol decoder

Bandwidth graphs

ICMP analysis

DNS parser

Reassembly of TCP streams

Final Deliverables

README with architecture diagram

Benchmarks

Clean codebase (headers, modules)

Demo video

🏁 What This Gives You

By the end of 2 months:

You understand networking at the byte level

You can parse packets manually

You’ve written privileged, concurrent, performance-critical C++

This is NOT a Wireshark clone — it’s a systems tool

This pairs perfectly with:

Your network analytics FastAPI project

Your ML traffic modeling ideas

A future kernel / eBPF project

If you want, next I can:

Turn this into a weekly calendar

Define exact DeepPacket architecture files

Tell you where to stop to avoid overengineering

Or rank how this stacks vs typical senior-year projects

Just tell me.



Run the following to run the project:
- Navigate to project-root folder

```bash
rm -rf build
cmake -B build
cmake --build build
```

Then run the build file

```bash
./build/packet-sniffer
```

