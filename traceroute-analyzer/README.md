# Traceroute Analyzer

Reconstructs a traceroute path from a raw packet capture — handling both major traceroute implementations and IP fragmentation, without any packet-parsing library.

## What it does

`ip_analyzer.py` hand-decodes pcap → Ethernet → IPv4, then correlates probes with responses to reconstruct the hop-by-hop path:

- **Both traceroute styles**: Linux's UDP-probe-based traceroute (ports 33434-33529) and Windows' ICMP-Echo-based `tracert`
- Matches ICMP Type 11 (TTL Exceeded), Type 3 Code 3 (Port Unreachable), and Type 0 (Echo Reply) responses back to the probe that triggered them
- Handles ECMP (multiple routers responding at the same TTL) and out-of-order hop arrival
- Detects IP fragmentation (MF flag, fragment offset) and reports fragment counts
- Reports per-hop RTT (mean ± standard deviation)

Two supporting scripts build on it: `enhanced_analyzer.py` subclasses the analyzer to count probes sent per TTL, and `cross_trace_rtt_comparison.py` shells out to `ip_analyzer.py` across multiple trace files and compares RTT for the same router across traces.

## Build & run

```bash
python3 ip_analyzer.py samples/<trace>.pcap
```

## Verified output

Linux UDP-based traceroute (`samples/group1-trace1.pcap`):

```
The IP address of the source node: 192.168.100.17
The IP address of ultimate destination node: 8.8.8.8
The IP addresses of the intermediate destination nodes:
	router 1: 142.104.68.167 (TTL=1)
	router 2: 142.104.68.1 (TTL=2)
	router 3: 192.168.9.5 (TTL=3)
	...
	router 16: 209.85.249.153 (TTL=13)
================================================================
The values in the protocol field of IP headers:
	1: ICMP
	17: UDP
================================================================
The number of fragments created from the original datagram is: 0
```

Windows ICMP-based traceroute (`samples/win_trace1.pcap`) resolves the same style of hop list from ICMP Echo instead of UDP probes.

Fragmentation handling (`samples/traceroute-frag.pcap`) correctly reports non-zero fragment counts and per-hop RTT statistics for a fragmented trace.
