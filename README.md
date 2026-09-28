[![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Topic](https://img.shields.io/badge/topic-raw%20sockets%20%26%20pcap-informational)]()

# Network Protocol Tools

Three Python tools that work directly at the packet level — no `scapy`, `dpkt`, or `requests` — parsing raw bytes by hand against the actual protocol specs.

| Project | What it does |
|---|---|
| [`http-client/`](http-client/) | A raw-socket HTTP/HTTPS client: redirects, cookies, HTTP/2 detection, auth detection |
| [`tcp-analyzer/`](tcp-analyzer/) | Parses a pcap file and reports per-connection TCP state, duration, and RTT |
| [`traceroute-analyzer/`](traceroute-analyzer/) | Reconstructs a traceroute path from a pcap, handling both Linux (UDP) and Windows (ICMP) traceroute styles |

## Stack

Python 3, standard library only (`socket`, `ssl`, `struct`) — every pcap/Ethernet/IP/TCP/ICMP parser here is hand-rolled against the format spec, not delegated to a packet-parsing library.

## Running

Each tool is a standalone script; see its own README for exact usage and verified sample output.

## 🎓 Project Context

Built as part of **CSC 361: Computer Communications and Networks** at the University
of Victoria (Fall 2025).

## ⚠️ Academic Integrity Notice

This repository is maintained for portfolio and educational purposes only. If you are
currently enrolled in CSC 361 at the University of Victoria or a similar networks
course, please note that using this code in your own assignments may constitute a
violation of Academic Integrity policies.
