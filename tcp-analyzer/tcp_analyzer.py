#!/usr/bin/env python3
"""
TCP Traffic Analysis
Parses a libpcap (.cap/.pcap) file, filters TCP over IPv4 on Ethernet II,
and outputs per-connection summaries.

Requirements: Python 3 standard library only.
"""

import sys
import struct
from collections import defaultdict, deque
from typing import Tuple, Optional, Dict, List

# ---------------------- Utilities ----------------------

def inet4(addr_bytes: bytes) -> str:
    return ".".join(str(b) for b in addr_bytes)

def parse_pcap_global_header(f):
    ghdr = f.read(24)
    if len(ghdr) < 24:
        raise ValueError("File too short for pcap global header")
    magic = ghdr[:4]
    if magic == b'\xd4\xc3\xb2\xa1':  # little-endian
        endian = '<'
        ns = False
    elif magic == b'\xa1\xb2\xc3\xd4':  # big-endian
        endian = '>'
        ns = False
    elif magic == b'\x4d\x3c\xb2\xa1':  # little-endian, nanosecond
        endian = '<'
        ns = True
    elif magic == b'\xa1\xb2\x3c\x4d':  # big-endian, nanosecond
        endian = '>'
        ns = True
    else:
        endian = '<'
        ns = False
    return endian, ns

def parse_pcap_pkthdr(f, endian: str):
    hdr = f.read(16)
    if len(hdr) < 16:
        return None
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
    return ts_sec, ts_usec, incl_len, orig_len

def timestamp_to_float(ts_sec: int, ts_sub: int, ns: bool) -> float:
    denom = 1_000_000_000 if ns else 1_000_000
    return ts_sec + (ts_sub / denom)

# ---------------------- Parsers ----------------------

ETH_HDR_LEN = 14

def parse_eth(pkt: bytes):
    if len(pkt) < ETH_HDR_LEN:
        return None
    eth_type = struct.unpack('!H', pkt[12:14])[0]
    return eth_type, pkt[ETH_HDR_LEN:]

def parse_ipv4(pkt: bytes):
    if len(pkt) < 20:
        return None
    vihl = pkt[0]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or len(pkt) < ihl:
        return None
    total_len = struct.unpack('!H', pkt[2:4])[0]
    proto = pkt[9]
    src = inet4(pkt[12:16])
    dst = inet4(pkt[16:20])
    flags_frag = struct.unpack('!H', pkt[6:8])[0]
    df = (flags_frag & 0x4000) != 0
    mf = (flags_frag & 0x2000) != 0
    frag_offset = (flags_frag & 0x1FFF) * 8
    payload = pkt[ihl: total_len]
    return {
        'ihl': ihl,
        'total_len': total_len,
        'proto': proto,
        'src': src,
        'dst': dst,
        'df': df,
        'mf': mf,
        'frag_offset': frag_offset,
        'payload': payload
    }

def parse_tcp(pkt: bytes):
    if len(pkt) < 20:
        return None
    sport, dport, seq, ack, off_flags, window, checksum, urgptr = struct.unpack('!HHIIHHHH', pkt[:20])
    data_offset = (off_flags >> 12) * 4
    if len(pkt) < data_offset:
        return None
    flags = off_flags & 0x01FF
    FIN = (flags & 0x001) != 0
    SYN = (flags & 0x002) != 0
    RST = (flags & 0x004) != 0
    PSH = (flags & 0x008) != 0
    ACK = (flags & 0x010) != 0
    URG = (flags & 0x020) != 0
    payload = pkt[data_offset:]
    return {
        'sport': sport, 'dport': dport,
        'seq': seq, 'ack': ack,
        'data_offset': data_offset,
        'flags': {'FIN': FIN, 'SYN': SYN, 'RST': RST, 'PSH': PSH, 'ACK': ACK, 'URG': URG},
        'window': window,
        'payload_len': len(payload),
        'payload': payload
    }

# ---------------------- Connection tracking ----------------------

class Conn:
    def __init__(self):
        self.first_ts = None
        self.first_syn_ts = None
        self.last_fin_ts = None
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.syn_count = 0
        self.fin_count = 0
        self.rst_seen = False
        self.first_segment_is_syn = None
        self.seen_any_packet = False
        self.pkts_src_to_dst = 0
        self.pkts_dst_to_src = 0
        self.bytes_src_to_dst = 0
        self.bytes_dst_to_src = 0
        self.data_after_fin = False
        self.any_fin_seen = False
        self.rtt_samples = []
        self._pending_acks_A = defaultdict(deque)
        self._pending_acks_B = defaultdict(deque)
        self.recv_windows = []
        self.sideA = None
        self.sideB = None

    def update_orientation(self, ip_src, sport, ip_dst, dport, is_syn_noack):
        if self.sideA is None:
            self.sideA = (ip_src, sport)
            self.sideB = (ip_dst, dport)
        if self.src_ip is None and is_syn_noack:
            self.src_ip, self.src_port = ip_src, sport
            self.dst_ip, self.dst_port = ip_dst, dport

    def is_complete(self):
        return self.syn_count >= 1 and self.fin_count >= 1

    def status_str(self):
        s = f"S{self.syn_count}F{self.fin_count}"
        if self.rst_seen:
            return f"{s} R"
        return s

    def _direction_is_src_to_dst(self, ip_src, sport):
        if self.src_ip is not None:
            return (ip_src == self.src_ip and sport == self.src_port)
        if self.sideA is None:
            return None
        return (ip_src == self.sideA[0] and sport == self.sideA[1])

    def _record_rtt_send(self, direction_is_A, seq, seg_len, ts):
        if seg_len <= 0:
            return
        expected_ack = (seq + seg_len) & 0xFFFFFFFF
        pend = self._pending_acks_A if direction_is_A else self._pending_acks_B
        pend[expected_ack].append(ts)

    def _record_rtt_ack(self, direction_is_A, acknum, ts):
        pend = self._pending_acks_B if direction_is_A else self._pending_acks_A
        dq = pend.get(acknum)
        if dq and len(dq) > 0:
            send_ts = dq.popleft()
            rtt = ts - send_ts
            if rtt >= 0:
                self.rtt_samples.append(rtt)

    def feed_packet(self, ts, ip_src, sport, ip_dst, dport, tcp):
        self.seen_any_packet = True
        flags = tcp['flags']
        syn = 1 if flags.get('SYN', False) else 0
        fin = 1 if flags.get('FIN', False) else 0
        rst = flags.get('RST', False)
        ack_flag = flags.get('ACK', False)
        payload_len = tcp['payload_len']
        window = tcp['window']

        if self.first_ts is None:
            self.first_ts = ts
            self.first_segment_is_syn = bool(syn and not ack_flag)

        self.update_orientation(ip_src, sport, ip_dst, dport, is_syn_noack=(syn and not ack_flag))

        if flags.get('SYN', False):
            self.syn_count += 1
            if self.first_syn_ts is None:
                self.first_syn_ts = ts
        if flags.get('FIN', False):
            self.fin_count += 1
            self.any_fin_seen = True
            self.last_fin_ts = ts
        if rst:
            self.rst_seen = True

        if self.any_fin_seen and payload_len > 0:
            self.data_after_fin = True

        is_src_to_dst = self._direction_is_src_to_dst(ip_src, sport)
        if is_src_to_dst is True:
            self.pkts_src_to_dst += 1
            self.bytes_src_to_dst += payload_len
        elif is_src_to_dst is False:
            self.pkts_dst_to_src += 1
            self.bytes_dst_to_src += payload_len

        self.recv_windows.append(int(window))

        direction_is_A = (self.sideA is not None and (ip_src, sport) == self.sideA)
        seg_len = payload_len + (1 if flags.get('SYN', False) else 0) + (1 if flags.get('FIN', False) else 0)
        if seg_len > 0:
            self._record_rtt_send(direction_is_A, tcp['seq'], seg_len, ts)

        if flags.get('ACK', False):
            self._record_rtt_ack(direction_is_A, tcp['ack'], ts)

def analyze_pcap(path: str):
    connections = {}
    with open(path, 'rb') as f:
        endian, ns = parse_pcap_global_header(f)
        first_ts = None
        while True:
            pkthdr = parse_pcap_pkthdr(f, endian)
            if pkthdr is None:
                break
            ts_sec, ts_sub, incl_len, orig_len = pkthdr
            pkt = f.read(incl_len)
            if len(pkt) < incl_len:
                break
            abs_ts = timestamp_to_float(ts_sec, ts_sub, ns)
            if first_ts is None:
                first_ts = abs_ts
            rel_ts = abs_ts - first_ts
            eth = parse_eth(pkt)
            if not eth:
                continue
            eth_type, payload = eth
            if eth_type != 0x0800:
                continue
            ip = parse_ipv4(payload)
            if not ip or ip['proto'] != 6 or ip['frag_offset'] != 0:
                continue
            tcp = parse_tcp(ip['payload'])
            if not tcp:
                continue
            src = (ip['src'], tcp['sport'])
            dst = (ip['dst'], tcp['dport'])
            key = tuple(sorted([src, dst]))
            if key not in connections:
                connections[key] = Conn()
            conn = connections[key]
            conn.feed_packet(rel_ts, ip['src'], tcp['sport'], ip['dst'], tcp['dport'], tcp)
    return connections

def output_report(connections, out):
    # Keep insertion order (first seen) -> chronological enough for this trace
    conns = list(connections.values())

    # ---------- A) ----------
    print(f"A) Total number of connections: {len(conns)}", file=out)
    print("", file=out)

    # ---------- B) ----------
    print("B) Connections' details:", file=out)
    print("", file=out)

    def conn_has_details(c) -> bool:
        # Match sample: details shown for connections that saw at least one FIN.
        return getattr(c, "fin_count", 0) > 0

    for i, c in enumerate(conns, 1):
        # Resolve endpoint labels (prefer inferred client/server; fall back to sideA/B)
        s_ip = c.src_ip if c.src_ip is not None else (c.sideA[0] if c.sideA else "")
        s_port = c.src_port if c.src_port is not None else (c.sideA[1] if c.sideA else 0)
        d_ip = c.dst_ip if c.dst_ip is not None else (c.sideB[0] if c.sideB else "")
        d_port = c.dst_port if c.dst_port is not None else (c.sideB[1] if c.sideB else 0)

        print(f"Connection {i}:", file=out)
        print(f"Source Address: {s_ip}", file=out)
        print(f"Destination address: {d_ip}", file=out)
        print(f"Source Port: {s_port}", file=out)
        print(f"Destination Port: {d_port}", file=out)
        
        # Status formatting: SxFy, and append " R" if any reset occurred
        status = f"S{c.syn_count}F{c.fin_count}"
        if c.rst_seen:
            status += " R"
        print(f"Status: {status}", file=out)

        # Detailed block only when at least one FIN appeared (matches sample behavior)
        if conn_has_details(c):
            start = c.first_syn_ts if c.first_syn_ts is not None else c.first_ts
            end = c.last_fin_ts if c.last_fin_ts is not None else start
            duration = (end - start) if (start is not None and end is not None) else 0.0

            # Units must be "seconds" (not "s")
            print(f"Start time: {start:.6f} seconds", file=out)
            print(f"End Time: {end:.6f} seconds", file=out)
            print(f"Duration: {duration:.6f} seconds", file=out)

            print(f"Number of packets sent from Source to Destination: {c.pkts_src_to_dst}", file=out)
            print(f"Number of packets sent from Destination to Source: {c.pkts_dst_to_src}", file=out)
            print(f"Total number of packets: {c.pkts_src_to_dst + c.pkts_dst_to_src}", file=out)
            print(f"Number of data bytes sent from Source to Destination: {c.bytes_src_to_dst}", file=out)
            print(f"Number of data bytes sent from Destination to Source: {c.bytes_dst_to_src}", file=out)
            print(f"Total number of data bytes: {c.bytes_src_to_dst + c.bytes_dst_to_src}", file=out)

        print("END", file=out)

        # Separator exactly as in sample (blank line, +++++, blank line) between connections only
        if i < len(conns):
            print("", file=out)
            print("+++++++++++++++++++++++++++++++++", file=out)
            print("", file=out)
        else:
            print("", file=out)  # single blank line after last "END" before section C

    # ---------- C) ----------
    print("C) General", file=out)
    print("", file=out)

    complete_conns = [c for c in conns if (c.syn_count >= 1 and c.fin_count >= 1)]
    reset_count = sum(1 for c in conns if c.rst_seen)
    # In the sample, "still open" == not complete
    still_open_count = sum(1 for c in conns if c.fin_count == 0)
    established_before = sum(1 for c in conns if c.first_segment_is_syn is False)

    print(f"The total number of complete TCP connections: {len(complete_conns)}", file=out)
    print(f"The number of reset TCP connections: {reset_count}", file=out)
    print(f"The number of TCP connections that were still open when the trace capture ended: {still_open_count}", file=out)
    print(f"The number of TCP connections established before the capture started: {established_before}", file=out)
    print("", file=out)

    # ---------- D) ----------
    print("D) Complete TCP connections:", file=out)
    print("", file=out)

    if complete_conns:
        # Duration stats (based on first SYN to last FIN for each complete connection)
        durations = []
        for c in complete_conns:
            start = c.first_syn_ts if c.first_syn_ts is not None else c.first_ts
            end = c.last_fin_ts if c.last_fin_ts is not None else start
            dur = (end - start) if (start is not None and end is not None) else 0.0
            durations.append(dur)

        print(f"Minimum time duration: {min(durations):.6f} seconds", file=out)
        print(f"Mean time duration: {sum(durations)/len(durations):.6f} seconds", file=out)
        print(f"Maximum time duration: {max(durations):.6f} seconds", file=out)
        print("", file=out)

        # RTT stats across all complete connections
        all_rtts = []
        for c in complete_conns:
            all_rtts.extend(c.rtt_samples)

        if all_rtts:
            print(f"Minimum RTT value: {min(all_rtts):.6f} seconds", file=out)
            print(f"Mean RTT value: {sum(all_rtts)/len(all_rtts):.6f} seconds", file=out)
            print(f"Maximum RTT value: {max(all_rtts):.6f} seconds", file=out)
        else:
            print("Minimum RTT value: N/A", file=out)
            print("Mean RTT value: N/A", file=out)
            print("Maximum RTT value: N/A", file=out)
        print("", file=out)

        # Packet counts (sum of both directions) per complete connection
        pkt_counts = [(c.pkts_src_to_dst + c.pkts_dst_to_src) for c in complete_conns]
        print(f"Minimum number of packets including both send/received: {min(pkt_counts)}", file=out)
        print(f"Mean number of packets including both send/received: {sum(pkt_counts)/len(pkt_counts):.6f}", file=out)
        print(f"Maximum number of packets including both send/received: {max(pkt_counts)}", file=out)
        print("", file=out)

        # Receive window sizes across all packets of complete connections
        all_windows = []
        for c in complete_conns:
            all_windows.extend(c.recv_windows)

        if all_windows:
            print(f"Minimum receive window size including both send/received: {min(all_windows)} bytes", file=out)
            print(f"Mean receive window size including both send/received: {sum(all_windows)/len(all_windows):.6f} bytes", file=out)
            print(f"Maximum receive window size including both send/received: {max(all_windows)} bytes", file=out)
        else:
            print("Minimum receive window size including both send/received: N/A", file=out)
            print("Mean receive window size including both send/received: N/A", file=out)
            print("Maximum receive window size including both send/received: N/A", file=out)
    else:
        print("No complete TCP connections found", file=out)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tcp_analyzer.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    base = pcap_path.rsplit('.', 1)[0]
    out_path = base + "_output.out"

    conns = analyze_pcap(pcap_path)
    with open(out_path, "w") as f:
        output_report(conns, f)

    print(f"Output written to {out_path}")

if __name__ == "__main__":
    main()
