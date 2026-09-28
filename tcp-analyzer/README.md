# TCP Analyzer

Parses a `.cap`/`.pcap` file and reports every TCP connection it finds, without any packet-parsing library.

## What it does

Manually decodes the pcap global header and per-packet headers (handling both byte orders), then walks each packet through Ethernet → IPv4 → TCP. Each unique 4-tuple becomes a `Conn`, tracked through its SYN/FIN/RST flags to determine connection state, duration, estimated RTT (from the first cumulative ACK match), and receive-window statistics (min/mean/max).

## Build & run

```bash
python3 tcp_analyzer.py samples/sample-capture-file.cap
```

Writes `<capture-file>_output.out` next to the input file.

**Verified** against the included sample capture — 48 connections detected. First connection in the output:

```
A) Total number of connections: 48

B) Connections' details:

Connection 1:
Source Address: 192.168.1.164
Destination address: 142.104.5.64
Source Port: 1200
Destination Port: 80
Status: S2F1 R
Start time: 0.000000 seconds
End Time: 43.612948 seconds
Duration: 43.612948 seconds
Number of packets sent from Source to Destination: 54
Number of packets sent from Destination to Source: 77
```
