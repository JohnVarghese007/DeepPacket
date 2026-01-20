# DeepPacket 
- A zero-copy network packet inspection tool with live capture, protocol parsing and validation.
- STATUS: WIP

## Overview
- DeepPacket is a network packet inspection tool inspired by Wireshark.
- It captures raw Ethernet frames, parses protocol layers and validates packet fields with a zero-copy design to minimize parser overhead.
- Main goal was to build something similar to wireshark at least on a very tiny scale.

## Features

### Current Features
- Live packet capture using Linux sockets
- Zero-copy parsing + Validation pipeline that currently supports the following:
    - IPv4
    - ARP
    - TCP
    - UDP
- Very very minimal GUI with working start/stop capture
- Real time display of parsed packet fields with validation results

### Planned Features:
- IPv6 support yet to be added to parser + validation which is literally most of the traffic
- Other protocols may be optionally added
- More polish for GUI

## Build
- This Project uses CMake
- Run the following to run the project:
    - Navigate to project-root folder

```bash
rm -rf build
cmake -B build
cmake --build build
```
- Then run the build file
```bash
sudo ./build/app/DeepPacketUI
```


