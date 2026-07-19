# CodeAlpha_NetworkSniffer

A basic network packet sniffer built in Python using **Scapy**, developed as part of the CodeAlpha Cybersecurity Internship (Task 1).

## Overview

This tool captures live network traffic and displays, for each packet:
- Source and destination IP addresses
- Transport-layer protocol (ICMP, TCP, UDP)
- Source/destination ports (for TCP/UDP)
- A preview of the raw payload

It also supports BPF filters (e.g. `icmp`, `tcp port 80`) to capture only relevant traffic instead of all network noise.

## Learning objectives

- Understand how data flows across a network as discrete packets
- Learn the structure of common protocols (Ethernet → IP → TCP/UDP/ICMP)
- Practice reading and interpreting captured packets
- Understand why unencrypted traffic exposes readable payloads, while encrypted traffic (HTTPS) does not

## 🛠 Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- **Windows**: [Npcap](https://npcap.com/) (install with "WinPcap API-compatible Mode" checked)
- **Linux**: no extra driver needed (uses native raw sockets)
- Administrator / root privileges (required to capture raw packets)

##  Installation

```bash
pip install scapy
```

## Usage

Run with elevated privileges:

**Windows** (as Administrator):
```powershell
python sniffer.py
```

**Linux**:
```bash
sudo python3 sniffer.py
```

While the script is running, generate traffic in another terminal, e.g.:
```bash
ping google.com
```

## Code walkthrough

```python
from scapy.all import sniff, IP, TCP, UDP, Raw

PROTOCOLES = {1: "ICMP", 6: "TCP", 17: "UDP"}

def afficher_paquet(paquet):
    if paquet.haslayer(IP):
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
        proto_num = paquet[IP].proto
        proto_nom = PROTOCOLES.get(proto_num, f"Autre({proto_num})")

        ligne = f"[{proto_nom}] {ip_src} -> {ip_dst}"

        if paquet.haslayer(TCP):
            ligne += f" | Port: {paquet[TCP].sport} -> {paquet[TCP].dport}"
        elif paquet.haslayer(UDP):
            ligne += f" | Port: {paquet[UDP].sport} -> {paquet[UDP].dport}"

        if paquet.haslayer(Raw):
            payload = bytes(paquet[Raw].load)
            ligne += f" | Payload: {payload[:20]}"

        print(ligne)

sniff(filter="icmp", prn=afficher_paquet, count=10)
```

- **`sniff()`** intercepts packets on the active network interface and calls `afficher_paquet()` for each one.
- **`haslayer(IP)`** ensures the packet contains an IP layer before extracting fields.
- **`PROTOCOLES`** maps raw protocol numbers to human-readable names.
- **`filter="icmp"`** applies a BPF filter so only ICMP (ping) traffic is captured — reducing noise and improving performance.
- **`Raw`** layer, when present, contains the unparsed payload — readable in plaintext protocols, unreadable (encrypted) in HTTPS.

## 📸 Example output

```
[ICMP] 192.168.100.20 -> 192.168.100.1 | Payload: b'\xe9Nj\x00\x00\x00...'
[ICMP] 192.168.100.1 -> 192.168.100.20 | Payload: b'\xe9Nj\x00\x00\x00...'
```

## Disclaimer

This tool is intended strictly for **educational purposes**, to be used only on networks and machines you own or have explicit authorization to monitor. Unauthorized packet interception may violate local laws and regulations.

##  Author

CodeAlpha Cybersecurity Internship — Task 1: Basic Network Sniffer
