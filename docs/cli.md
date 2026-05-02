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
  - live <iface> — start live capture
  - stop — stop live capture
  - read <pcap> — load and summarize a PCAP file
  - view <index> — detailed packet breakdown in text form
  - export <pcap> — export current capture to PCAP
  - info, help, quit