## DeepPacket
- A C++ Network Packet Parser with Validation for Network Protocols


# Overview
- DeepPacket is a modular zero-copy C++ engine for parsing  raw network packets
- Inspired by Wireshark and aim to creaate a similar packet inspection tool

# Features

Current Features
- Simulated Network Packets for Parsing
- Completed minimal parser layer

Planned Features:
- Packet validation pipeline
- Raw Packet capture to replace simulated static packets
- Possible imgui addition if all goes well

# Build
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


