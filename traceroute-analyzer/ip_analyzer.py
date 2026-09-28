#!/usr/bin/env python3
"""
IP Protocol Analysis
Analyzes traceroute packet captures to extract IP-level information.

Requirements: Python 3 standard library only (no external pcap libraries).
"""

import sys
import struct
import math
from collections import defaultdict
from typing import Tuple, Optional, Dict, List

# ---------------------- Utilities ----------------------

def inet4(addr_bytes: bytes) -> str:
    """Convert 4-byte IP address to dotted decimal string."""
    return ".".join(str(b) for b in addr_bytes)

def parse_pcap_global_header(f):
    """Parse the global PCAP file header."""
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
    """Parse a packet header from PCAP file."""
    hdr = f.read(16)
    if len(hdr) < 16:
        return None
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
    return ts_sec, ts_usec, incl_len, orig_len

def timestamp_to_float(ts_sec: int, ts_sub: int, ns: bool) -> float:
    """Convert timestamp to float seconds."""
    denom = 1_000_000_000 if ns else 1_000_000
    return ts_sec + (ts_sub / denom)

# ---------------------- Parsers ----------------------

ETH_HDR_LEN = 14

def parse_eth(pkt: bytes):
    """Parse Ethernet header."""
    if len(pkt) < ETH_HDR_LEN:
        return None
    eth_type = struct.unpack('!H', pkt[12:14])[0]
    return eth_type, pkt[ETH_HDR_LEN:]

def parse_ipv4(pkt: bytes):
    """Parse IPv4 header and return detailed information."""
    if len(pkt) < 20:
        return None
    
    vihl = pkt[0]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    
    if version != 4 or len(pkt) < ihl:
        return None
    
    total_len = struct.unpack('!H', pkt[2:4])[0]
    identification = struct.unpack('!H', pkt[4:6])[0]
    flags_frag = struct.unpack('!H', pkt[6:8])[0]
    ttl = pkt[8]
    proto = pkt[9]
    src = inet4(pkt[12:16])
    dst = inet4(pkt[16:20])
    
    # Fragment flags
    df = (flags_frag & 0x4000) != 0
    mf = (flags_frag & 0x2000) != 0
    frag_offset = (flags_frag & 0x1FFF) * 8  # in bytes
    
    payload = pkt[ihl:total_len] if total_len <= len(pkt) else pkt[ihl:]
    
    return {
        'ihl': ihl,
        'total_len': total_len,
        'identification': identification,
        'ttl': ttl,
        'proto': proto,
        'src': src,
        'dst': dst,
        'df': df,
        'mf': mf,
        'frag_offset': frag_offset,
        'payload': payload
    }

def parse_icmp(pkt: bytes):
    """Parse ICMP header."""
    if len(pkt) < 8:
        return None
    
    icmp_type = pkt[0]
    icmp_code = pkt[1]
    checksum = struct.unpack('!H', pkt[2:4])[0]
    
    result = {
        'type': icmp_type,
        'code': icmp_code,
        'checksum': checksum
    }
    
    # For ICMP Echo Request/Reply (type 8 or 0)
    if icmp_type in [0, 8]:
        if len(pkt) >= 8:
            identifier = struct.unpack('!H', pkt[4:6])[0]
            sequence = struct.unpack('!H', pkt[6:8])[0]
            result['identifier'] = identifier
            result['sequence'] = sequence
            result['payload'] = pkt[8:]
    
    # For ICMP TTL Exceeded (type 11) or Destination Unreachable (type 3)
    elif icmp_type in [3, 11]:
        # The data contains the IP header + first 64 bits of original datagram
        if len(pkt) > 8:
            result['original_data'] = pkt[8:]
    
    return result

def parse_udp(pkt: bytes):
    """Parse UDP header."""
    if len(pkt) < 8:
        return None
    
    sport = struct.unpack('!H', pkt[0:2])[0]
    dport = struct.unpack('!H', pkt[2:4])[0]
    length = struct.unpack('!H', pkt[4:6])[0]
    checksum = struct.unpack('!H', pkt[6:8])[0]
    
    return {
        'sport': sport,
        'dport': dport,
        'length': length,
        'checksum': checksum,
        'payload': pkt[8:]
    }

# ---------------------- Traceroute Analysis ----------------------

class TracerouteAnalyzer:
    def __init__(self):
        self.source_ip = None
        self.dest_ip = None
        self.intermediate_routers = {}  # TTL -> list of router IPs
        self.protocols = set()
        self.fragments = {}  # identification -> fragment info
        self.rtt_data = defaultdict(list)  # router_ip -> list of RTTs
        self.sent_packets = {}  # key -> (timestamp, packet_info)
        self.ttl_sent = {}  # packet_id -> original TTL when sent
        self.total_packets = 0  # Track total packets processed
        self.relevant_packets = 0  # Track only ICMP + UDP packets
        
    def analyze_pcap(self, path: str):
        """Main analysis function."""
        with open(path, 'rb') as f:
            endian, ns = parse_pcap_global_header(f)
            
            while True:
                pkthdr = parse_pcap_pkthdr(f, endian)
                if pkthdr is None:
                    break
                
                ts_sec, ts_sub, incl_len, orig_len = pkthdr
                pkt = f.read(incl_len)
                if len(pkt) < incl_len:
                    break
                
                timestamp = timestamp_to_float(ts_sec, ts_sub, ns)
                self.total_packets += 1
                self.process_packet(pkt, timestamp)
    
    def process_packet(self, pkt: bytes, timestamp: float):
        """Process a single packet."""
        # Parse Ethernet
        eth = parse_eth(pkt)
        if not eth or eth[0] != 0x0800:  # IPv4
            return
        
        # Parse IP
        ip = parse_ipv4(eth[1])
        if not ip:
            return
        
        # Track protocols (only ICMP and UDP for traceroute)
        if ip['proto'] in [1, 17]:  # ICMP or UDP
            self.protocols.add(ip['proto'])
            self.relevant_packets += 1  # Count only ICMP/UDP packets
        
        # Track fragmentation
        if ip['identification'] != 0:
            self.track_fragmentation(ip)
        
        # Determine packet direction and type
        if ip['proto'] == 17:  # UDP
            self.process_udp_packet(ip, timestamp)
        elif ip['proto'] == 1:  # ICMP
            self.process_icmp_packet(ip, timestamp)
    
    def track_fragmentation(self, ip: dict):
        """Track IP fragmentation information."""
        frag_id = ip['identification']
        
        if frag_id not in self.fragments:
            self.fragments[frag_id] = {
                'count': 0,
                'fragments': [],
                'has_more': False
            }
        
        frag_info = self.fragments[frag_id]
        frag_info['count'] += 1
        frag_info['fragments'].append({
            'offset': ip['frag_offset'],
            'mf': ip['mf'],
            'size': ip['total_len'] - ip['ihl']
        })
        
        if ip['mf']:
            frag_info['has_more'] = True
    
    def process_udp_packet(self, ip: dict, timestamp: float):
        """Process UDP packet (outgoing traceroute probe)."""
        udp = parse_udp(ip['payload'])
        if not udp:
            return
        
        # Check if this is a traceroute UDP packet (port range 33434-33529)
        if not (33434 <= udp['dport'] <= 33529):
            return
        
        # This is the source node sending traceroute probes
        if self.source_ip is None:
            self.source_ip = ip['src']
            self.dest_ip = ip['dst']
        
        # Store sent packet for RTT calculation
        # Use source port as key for Linux traceroute
        key = ('udp', udp['sport'])
        self.sent_packets[key] = (timestamp, ip, udp)
        
        # Track the TTL of this packet
        self.ttl_sent[key] = ip['ttl']
    
    def process_icmp_packet(self, ip: dict, timestamp: float):
        """Process ICMP packet (could be echo request/reply or TTL exceeded)."""
        icmp = parse_icmp(ip['payload'])
        if not icmp:
            return
        
        # ICMP Echo Request (Windows traceroute)
        if icmp['type'] == 8:
            if self.source_ip is None:
                self.source_ip = ip['src']
                self.dest_ip = ip['dst']
            
            # Store for RTT calculation
            key = ('icmp_echo', icmp.get('sequence', 0))
            self.sent_packets[key] = (timestamp, ip, icmp)
            self.ttl_sent[key] = ip['ttl']
        
        # ICMP Echo Reply (from ultimate destination)
        elif icmp['type'] == 0:
            if self.dest_ip is None and ip['src'] != self.source_ip:
                self.dest_ip = ip['src']
            
            # Calculate RTT
            key = ('icmp_echo', icmp.get('sequence', 0))
            if key in self.sent_packets:
                sent_time, sent_ip, sent_icmp = self.sent_packets[key]
                rtt = (timestamp - sent_time) * 1000  # Convert to ms
                self.rtt_data[ip['src']].append(rtt)
        
        # ICMP Port Unreachable (type 3, code 3) - from ultimate destination when UDP probe arrives
        elif icmp['type'] == 3 and icmp['code'] == 3:
            # This means we reached the destination
            router_ip = ip['src']
            
            # Extract original packet info from ICMP payload
            if 'original_data' in icmp and len(icmp['original_data']) >= 20:
                orig_ip = parse_ipv4(icmp['original_data'])
                if orig_ip and orig_ip['proto'] == 17:  # UDP
                    # Match with sent packet for RTT
                    if len(icmp['original_data']) >= orig_ip['ihl'] + 4:
                        udp_header_start = orig_ip['ihl']
                        orig_sport = struct.unpack('!H', icmp['original_data'][udp_header_start:udp_header_start+2])[0]
                        
                        key = ('udp', orig_sport)
                        if key in self.sent_packets:
                            sent_time, sent_ip, sent_udp = self.sent_packets[key]
                            rtt = (timestamp - sent_time) * 1000  # Convert to ms
                            self.rtt_data[router_ip].append(rtt)
        
        # ICMP TTL Exceeded (from intermediate router)
        elif icmp['type'] == 11:
            router_ip = ip['src']
            
            # Extract original packet info from ICMP payload
            if 'original_data' in icmp and len(icmp['original_data']) >= 20:
                orig_ip = parse_ipv4(icmp['original_data'])
                if orig_ip:
                    # Calculate RTT based on protocol
                    if orig_ip['proto'] == 17:  # UDP (Linux traceroute)
                        ttl = self.match_udp_rtt(orig_ip, icmp, router_ip, timestamp)
                    elif orig_ip['proto'] == 1:  # ICMP (Windows traceroute)
                        ttl = self.match_icmp_rtt(orig_ip, icmp, router_ip, timestamp)
                    else:
                        ttl = None
                    
                    # Track intermediate router with correct TTL
                    if ttl is not None:
                        if ttl not in self.intermediate_routers:
                            self.intermediate_routers[ttl] = []
                        if router_ip not in self.intermediate_routers[ttl]:
                            self.intermediate_routers[ttl].append(router_ip)
    
    def match_udp_rtt(self, orig_ip: dict, icmp: dict, router_ip: str, timestamp: float):
        """Match UDP packet with ICMP error for RTT calculation. Returns TTL."""
        if len(icmp['original_data']) < orig_ip['ihl'] + 4:
            return None
        
        # Extract source port from original UDP header
        udp_header_start = orig_ip['ihl']
        orig_sport = struct.unpack('!H', icmp['original_data'][udp_header_start:udp_header_start+2])[0]
        
        key = ('udp', orig_sport)
        if key in self.sent_packets:
            sent_time, sent_ip, sent_udp = self.sent_packets[key]
            rtt = (timestamp - sent_time) * 1000  # Convert to ms
            self.rtt_data[router_ip].append(rtt)
            
            # Return the TTL from the sent packet
            return self.ttl_sent.get(key)
        
        return None
    
    def match_icmp_rtt(self, orig_ip: dict, icmp: dict, router_ip: str, timestamp: float):
        """Match ICMP echo with ICMP error for RTT calculation. Returns TTL."""
        if len(icmp['original_data']) < orig_ip['ihl'] + 8:
            return None
        
        # Extract sequence number from original ICMP echo
        icmp_header_start = orig_ip['ihl']
        orig_seq = struct.unpack('!H', icmp['original_data'][icmp_header_start+6:icmp_header_start+8])[0]
        
        key = ('icmp_echo', orig_seq)
        if key in self.sent_packets:
            sent_time, sent_ip, sent_icmp = self.sent_packets[key]
            rtt = (timestamp - sent_time) * 1000  # Convert to ms
            self.rtt_data[router_ip].append(rtt)
            
            # Return the TTL from the sent packet
            return self.ttl_sent.get(key)
        
        return None
    
    def get_protocol_name(self, proto_num: int) -> str:
        """Convert protocol number to name."""
        protocol_names = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocol_names.get(proto_num, f'Unknown({proto_num})')
    
    def calculate_statistics(self, values: List[float]) -> Tuple[float, float]:
        """Calculate mean and standard deviation."""
        if not values:
            return 0.0, 0.0
        
        mean = sum(values) / len(values)
        
        if len(values) == 1:
            return mean, 0.0
        
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        
        return mean, std_dev
    
    def print_report(self):
        """Generate the output report matching reference format."""
        # Header section
        print("================================================================")
        print(f"The IP address of the source node: {self.source_ip}")
        print(f"The IP address of ultimate destination node: {self.dest_ip}")
        
        # Intermediate routers - number them sequentially
        print("The IP addresses of the intermediate destination nodes:")
        router_num = 1
        for ttl in sorted(self.intermediate_routers.keys()):
            for router_ip in self.intermediate_routers[ttl]:
                print(f"\trouter {router_num}: {router_ip} (TTL={ttl})")
                router_num += 1
        
        print("================================================================")
        
        # Protocol field values
        print("The values in the protocol field of IP headers:")
        for proto in sorted(self.protocols):
            print(f"\t{proto}: {self.get_protocol_name(proto)}")
        
        print("================================================================")
        
        # Fragmentation information
        # According to Q&A: "Since the number of fragments and the offset in the last fragment remain
        # unchanged across various original datagrams, let's just print this information once"
        has_fragmentation = False
        frag_count = 0
        last_frag_offset = 0
        
        for frag_id, frag_info in self.fragments.items():
            if frag_info['count'] > 1 or frag_info['has_more']:
                has_fragmentation = True
                frag_count = frag_info['count']
                
                # Find last fragment (highest offset with MF=0)
                for frag in frag_info['fragments']:
                    if not frag['mf']:
                        # This is the last fragment
                        last_frag_offset = frag['offset']
                break  # Only report the first fragmented datagram
        
        if has_fragmentation:
            print(f"The number of fragments created from the original datagram is: {frag_count}")
            print(f"The offset of the last fragment is: {last_frag_offset}")
        else:
            print("The number of fragments created from the original datagram is: 0")
            print("The offset of the last fragment is: 0")
        print()
        
        print("================================================================")
        
        # RTT statistics - collect for summary table
        ttl_rtt_map = {}  # TTL -> average RTT
        
        # First, print RTT for each intermediate router
        for ttl in sorted(self.intermediate_routers.keys()):
            ttl_rtts = []
            for router_ip in self.intermediate_routers[ttl]:
                if router_ip in self.rtt_data and self.rtt_data[router_ip]:
                    avg, std = self.calculate_statistics(self.rtt_data[router_ip])
                    print(f"The avg RTT between {self.source_ip} and {router_ip} is: {avg:.6f} ms, the s.d. is: {std:.6f} ms")
                    ttl_rtts.append(avg)
            
            # Store average for this TTL
            if ttl_rtts:
                ttl_rtt_map[ttl] = sum(ttl_rtts) / len(ttl_rtts)
        
        # RTT to ultimate destination
        if self.dest_ip and self.dest_ip in self.rtt_data and self.rtt_data[self.dest_ip]:
            avg, std = self.calculate_statistics(self.rtt_data[self.dest_ip])
            print(f"The avg RTT between {self.source_ip} and {self.dest_ip} is: {avg:.6f} ms, the s.d. is: {std:.6f} ms")
        
        print("================================================================")
        print()
        
        # Summary table
        if ttl_rtt_map:
            print("TTL      Average RTT in this Trace File (ms)")
            for ttl in sorted(ttl_rtt_map.keys()):
                print(f"{ttl:<13}{ttl_rtt_map[ttl]:.2f}")
            print()
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ip_analyzer.py <pcap_file>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    
    # Print opening messages like reference output
    print(f"Opening pcap file: {pcap_path}")
    print("Global header read successfully.")
    print("Starting packet parsing...")
    
    analyzer = TracerouteAnalyzer()
    analyzer.analyze_pcap(pcap_path)
    
    print(f"Completed packet parsing. Total packets processed: {analyzer.relevant_packets}")
    
    analyzer.print_report()

if __name__ == "__main__":
    main()