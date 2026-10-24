# dpctl — Command Line Interface

`dpctl` is a lightweight REPL for interacting with DeepPacket from the terminal.

---

## Starting dpctl

```bash
sudo ./build/cli/dpctl
```
---

## Commands:
  - interfaces — list available network interfaces
  - live <iface> [filter] — start live capture with an optional native BPF capture filter
  - stop — stop live capture
  - read <pcap> — load and summarize a PCAP file
  - view <index> — detailed packet breakdown in text form
  - export <pcap> — export current capture to PCAP
  - info, help, quit

## Capture filters

Live filters use the same native DeepPacket syntax as the UI:

```text
live <interface> [filter]
```

Examples:

```text
live eth0
live eth0 tcp
live eth0 tcp and port 443
live eth0 host 192.168.1.10
live eth0 (tcp or udp) and port 443
```

Supported predicates are `tcp`, `udp`, `icmp`, `arp`, `host <IPv4
address>`, and `port <number>`. Supported operators are `and`, `or`, `not`,
and parentheses.

This is a kernel capture filter applied to live Linux `AF_PACKET` traffic
before packets enter the user-space queue. It is not a display filter and
does not filter packets already loaded from a PCAP file. The first version
assumes Ethernet II framing, does not handle VLAN tags, and rejects IPv4
options for fixed-offset port matching. It is a deliberately small native
subset, not full Wireshark or libpcap filter syntax.