# DeepPacket 
- A C++ Network Packet Parser with Validation for Network Protocols
- STATUS: WIP

## Overview
- DeepPacket is a modular zero-copy C++ tool for parsing  raw network packets
- Inspired by Wireshark and aim to create a similar packet inspection tool

## Features

### Current Features
- Completed minimal parser + validation + capture layers
- Parser + Validation currently works on live-packets(IPv4, TCP, UDP only)

### Planned Features:
- IPv6 support yet to be added to parser + validation which is literally most of the traffic
- Other protocols may be optionally added
- Possible imgui addition if all goes well

## Build
- This Project uses CMake
- Run the following to run the project:
    - Navigate to project-root folder

```bash
rm -rf build
cmake -B build
cmake --build build
```
- Then run the build file(saving output to a file for now)
```bash
sudo ./build/app/DeepPacket > output.txt
```


