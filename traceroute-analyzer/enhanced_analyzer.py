#!/usr/bin/env python3
"""
Enhanced analyzer that counts probes sent per TTL hop.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ip_analyzer import TracerouteAnalyzer, parse_pcap_global_header, parse_pcap_pkthdr, timestamp_to_float
from ip_analyzer import parse_eth, parse_ipv4, parse_udp, parse_icmp
from collections import defaultdict

class EnhancedAnalyzer(TracerouteAnalyzer):
    def __init__(self):
        super().__init__()
        self.probes_per_ttl = defaultdict(int)
        self.packets_by_ttl = defaultdict(list)
        
    def process_packet(self, pkt: bytes, timestamp: float):
        """Enhanced packet processing that counts probes."""
        # Call parent method
        super().process_packet(pkt, timestamp)
        
        # Parse for probe counting
        eth = parse_eth(pkt)
        if not eth or eth[0] != 0x0800:
            return
            
        ip = parse_ipv4(eth[1])
        if not ip:
            return
        
        # Count outgoing probes (UDP or ICMP echo)
        if ip['proto'] == 17:  # UDP
            udp = parse_udp(ip['payload'])
            if udp and 33434 <= udp['dport'] <= 33529:
                # This is an outgoing traceroute probe
                ttl = ip['ttl']
                self.probes_per_ttl[ttl] += 1
                self.packets_by_ttl[ttl].append({
                    'timestamp': timestamp,
                    'type': 'UDP',
                    'sport': udp['sport'],
                    'dport': udp['dport']
                })
        
        elif ip['proto'] == 1:  # ICMP
            icmp = parse_icmp(ip['payload'])
            if icmp and icmp['type'] == 8:  # Echo request
                # This is an outgoing traceroute probe (Windows style)
                ttl = ip['ttl']
                self.probes_per_ttl[ttl] += 1
                self.packets_by_ttl[ttl].append({
                    'timestamp': timestamp,
                    'type': 'ICMP',
                    'seq': icmp.get('sequence', 0)
                })
    
    def get_probes_summary(self):
        """Get summary of probes per TTL."""
        if not self.probes_per_ttl:
            return "No probes detected"
        
        # Find the most common probe count
        probe_counts = list(self.probes_per_ttl.values())
        most_common = max(set(probe_counts), key=probe_counts.count)
        
        result = f"Probes per TTL: {most_common}\n"
        result += f"\nDetailed breakdown:\n"
        for ttl in sorted(self.probes_per_ttl.keys()):
            result += f"  TTL {ttl}: {self.probes_per_ttl[ttl]} probes\n"
        
        return result

def analyze_file_enhanced(pcap_file):
    """Analyze a pcap file with enhanced probe counting."""
    analyzer = EnhancedAnalyzer()
    analyzer.analyze_pcap(pcap_file)
    
    print(f"\nAnalysis of: {pcap_file}")
    print("=" * 60)
    print(analyzer.get_probes_summary())
    print()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_file_enhanced(sys.argv[1])
    else:
        # Analyze all group files
        print("GROUP 1 ANALYSIS")
        print("=" * 70)
        for i in range(1, 6):
            analyze_file_enhanced(f'/mnt/user-data/uploads/group1-trace{i}.pcap')
        
        print("\n\nGROUP 2 ANALYSIS")
        print("=" * 70)
        for i in range(1, 6):
            analyze_file_enhanced(f'/mnt/user-data/uploads/group2-trace{i}.pcap')
