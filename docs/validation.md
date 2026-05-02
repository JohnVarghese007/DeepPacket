# Validation/Testing & Protocol Support Notes

DeepPacket implements a zero‑copy parser for all supported protocols.  
Each protocol is parsed directly from the raw packet buffer using pointer offsets, with no heap allocations or memcpy.

Validation is RFC‑aware and reports from a list of 50+ detailed error codes for malformed packets.
Each and every supported error gets its own test case in the test suite.

---

# Ethernet II

## Fields
- Destination MAC  
- Source MAC  
- EtherType  

## Validation
- Minimum frame length  
- Known/valid EtherType  

## Errors
- **TOO_SMALL_FOR_ETHERNET** — fewer than 14 bytes  
- **INVALID_ETHERTYPE** — unsupported or unknown EtherType  

---

# ARP

## Fields
- Hardware type  
- Protocol type  
- Hardware length  
- Protocol length  
- Opcode  
- Sender MAC / Sender IP  
- Target MAC / Target IP  

## Validation
- Ethernet hardware type  
- IPv4 protocol type  
- Correct address lengths  
- Valid opcode  
- Complete address fields  

## Errors
- **ARP_TRUNCATED_HEADER** — header shorter than 28 bytes  
- **ARP_INVALID_HTYPE** — hardware type not Ethernet  
- **ARP_INVALID_PTYPE** — protocol type not IPv4  
- **ARP_INVALID_HLEN** — hardware length not 6  
- **ARP_INVALID_PLEN** — protocol length not 4  
- **ARP_INVALID_OPCODE** — unsupported opcode  
- **ARP_TRUNCATED_ADDRESSES** — missing sender/target MAC/IP  
- **ARP_REPLY_TO_BROADCAST** — ARP reply sent to broadcast MAC  

---

# IPv4

## Fields
- Version  
- IHL (header length)  
- Total length  
- Identification  
- Flags  
- Fragment offset  
- TTL  
- Protocol  
- Header checksum  
- Source IP  
- Destination IP  
- Options (optional)  

## Validation
- Version == 4  
- IHL >= 5  
- Header length within packet  
- Total length >= header length  
- Total length <= actual packet size  
- Header checksum  
- Options not truncated  
- Fragmentation fields valid  

## Errors
- **MISSING_IPV4_HEADER**  
- **TOO_SMALL_FOR_IPV4**  
- **INVALID_IPV4_VERSION**  
- **INVALID_IPV4_IHL**  
- **INVALID_IPV4_IHL_LENGTH**  
- **INVALID_IPV4_TOTAL_LENGTH**  
- **IPV4_TOTAL_LENGTH_EXCEEDS_PACKET**  
- **IPV4_INVALID_CHECKSUM**  
- **IPV4_OPTIONS_TRUNCATED**  
- **IPV4_FRAGMENT_OFFSET_INVALID**  
- **IPV4_MORE_FRAGMENTS_INVALID**  

---

# IPv6 (Minimal)

## Fields
- Version  
- Traffic class  
- Flow label  
- Payload length  
- Next header  
- Hop limit  
- Source IP  
- Destination IP  

## Validation
- Version == 6  
- Payload length sanity  
- Payload fits in packet  
- Supported next header  
- Hop limit > 0  
- Extension header detection  

## Errors
- **MISSING_IPV6_HEADER**  
- **TOO_SMALL_FOR_IPV6**  
- **INVALID_IPV6_VERSION**  
- **INVALID_IPV6_PAYLOAD_LENGTH**  
- **IPV6_PAYLOAD_EXCEEDS_PACKET**  
- **IPV6_UNSUPPORTED_NEXT_HEADER**  
- **IPV6_HOP_LIMIT_ZERO**  
- **IPV6_EXTENSION_HEADER_PRESENT**  
- **IPV6_EXTENSION_HEADER_UNSUPPORTED**  
- **IPV6_EXTENSION_HEADER_TRUNCATED**  

---

# ICMPv4

## Fields
- Type  
- Code  
- Checksum  
- Embedded IPv4 header (for error messages)  

## Validation
- Known type  
- Valid code for type  
- Checksum  
- Embedded IPv4 header valid  

## Errors
- **MISSING_ICMPV4_HEADER**  
- **TOO_SMALL_FOR_ICMPV4**  
- **ICMPV4_INVALID_TYPE**  
- **ICMPV4_INVALID_CODE**  
- **ICMPV4_INVALID_CHECKSUM**  
- **ICMPV4_TRUNCATED_PAYLOAD**  
- **ICMPV4_EMBEDDED_IPV4_INVALID**  

---

# ICMPv6

## Fields
- Type  
- Code  
- Checksum  
- Embedded IPv6 header (for error messages)  

## Validation
- Known type  
- Valid code  
- Checksum  
- Embedded IPv6 header valid  
- Error message structure valid  

## Errors
- **ICMPV6_MISSING_HEADER**  
- **ICMPV6_TOO_SMALL**  
- **ICMPV6_INVALID_TYPE**  
- **ICMPV6_INVALID_CODE**  
- **ICMPV6_INVALID_CHECKSUM**  
- **ICMPV6_TRUNCATED_PAYLOAD**  
- **ICMPV6_EMBEDDED_IPV6_INVALID**  
- **ICMPV6_ERROR_MESSAGE_INVALID**  

---

# TCP

## Fields
- Source port  
- Destination port  
- Sequence number  
- Acknowledgment number  
- Data offset  
- Flags  
- Window size  
- Checksum  
- Urgent pointer  

## Validation
- Header length >= 20 bytes  
- Header length <= packet size  
- Checksum (skipped for live capture due to offload)  

## Errors
- **MISSING_TCP_HEADER**  
- **TOO_SMALL_FOR_TCP**  
- **INVALID_TCP_DATA_OFFSET**  
- **TCP_HEADER_EXCEEDS_PACKET**  
- **TCP_INVALID_CHECKSUM**  

---

# UDP

## Fields
- Source port  
- Destination port  
- Length  
- Checksum  

## Validation
- Length >= 8  
- Length <= packet size  
- Checksum (skipped for live capture)  

## Errors
- **MISSING_UDP_HEADER**  
- **TOO_SMALL_FOR_UDP**  
- **INVALID_UDP_LENGTH**  
- **UDP_LENGTH_EXCEEDS_PACKET**  
- **UDP_INVALID_CHECKSUM**  

---

# Miscellaneous

## Errors
- **UNSUPPORTED_IP_PROTOCOL** — protocol field not recognized (e.g., GRE, ESP, AH, etc.)

