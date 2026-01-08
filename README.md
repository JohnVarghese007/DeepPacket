# DeepPacket 
- A C++ Network Packet Parser with Validation for Network Protocols
- STATUS: WIP

## Overview
- DeepPacket is a modular zero-copy C++ tool for parsing  raw network packets
- Inspired by Wireshark and aim to create a similar packet inspection tool

## Features

### Current Features
- Simulated Network Packets for Parsing
- Completed minimal parser layer
- Parser + Validation currently works on synthetic packets, yet to be tested on real packets

### Planned Features:
- Packet validation pipeline
- Raw Packet capture to replace simulated static packets
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
- Then run the build file
```bash
./build/app/DeepPacket
```


