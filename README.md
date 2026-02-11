# DeepPacket 
- A zero-copy network packet inspection tool with live capture, protocol parsing and validation.
- STATUS: WIP

## Overview
- DeepPacket is a network packet inspection tool inspired by Wireshark.
- It captures raw Ethernet frames from a Linux network interface, parses protocol layers and validates packet fields with a zero-copy design to minimize parser overhead.
- Main goal was to build something similar to wireshark at least on a very tiny scale.

## Features

### Current Features
- Live packet capture using Linux sockets
- Zero-copy parsing + Validation pipeline that currently supports the following:
    - Ethernet
    - IPv4
    - ARP
    - TCP
    - UDP
    - ICMP
- Fairly extensive test suite
- Very minimal GUI (working start/stop capture and a hex dump)
- Real time display of parsed packet fields with validation results

### Planned Features:
- IPv6 support yet to be added to parser + validation 
- Multi-threaded pipeline (gui currently cannot keep up with capture/parser aand freezes a lot)
- Auto-detect / choose network interface (currently hardcoded into raw-capture.cpp as "enp0s3")
- Other protocols may be optionally added
- More polish for GUI

## Build
- This Project uses CMake
- Follow these steps to build the project:
    - Navigate to project-root folder
    - change interface name in parser/src/raw-capture.cpp (Currently hardcoded) and hit save.

- Now run the follwing in the terminal from the project-root

```bash
rm -rf build
cmake -B build
cmake --build build
```
- This project currently produces two executables
    - DeepPacketTests
    - DeepPacketUI

To run the test suite:
```bash
sudo ./build/tests/DeepPacketTests > output.txt
```

To run the GUI:
```bash
sudo ./build/app/DeepPacketUI
```
