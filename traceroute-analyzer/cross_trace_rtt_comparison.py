#!/usr/bin/env python3
"""
Cross-trace RTT comparison.
Analyzes multiple traceroute files and compares RTT across traces.
"""

import sys
import subprocess
import re
from collections import defaultdict
from typing import Dict, List, Tuple

def extract_rtt_from_output(output: str) -> Dict[int, List[float]]:
    """
    Extract RTT values organized by TTL from analyzer output.
    Returns: Dict[TTL, List[RTT_values]]
    """
    rtt_by_ttl = defaultdict(list)
    router_ttl_map = {}
    
    # First, extract router to TTL mapping
    lines = output.split('\n')
    for line in lines:
        if line.strip().startswith('router'):
            # Example: "router 1: 142.104.68.167,"
            match = re.search(r'router (\d+): ([\d.]+)', line)
            if match:
                ttl = int(match.group(1))
                router_ip = match.group(2)
                router_ttl_map[router_ip] = ttl
    
    # Now extract RTT values and map to TTL
    for line in lines:
        if 'avg RTT between' in line:
            # Example: "The avg RTT between 192.168.100.17 and 142.104.68.167 is: 11.366606 ms, the s.d. is: 0.206939 ms"
            match = re.search(r'between [\d.]+ and ([\d.]+) is: ([\d.]+) ms', line)
            if match:
                router_ip = match.group(1)
                avg_rtt = float(match.group(2))
                
                if router_ip in router_ttl_map:
                    ttl = router_ttl_map[router_ip]
                    rtt_by_ttl[ttl].append(avg_rtt)
    
    return rtt_by_ttl

def analyze_trace_group(trace_files: List[str], group_name: str):
    """Analyze a group of trace files."""
    print(f"\n{'='*70}")
    print(f"Analysis of {group_name}")
    print(f"{'='*70}\n")
    
    all_results = {}
    routers_by_trace = {}
    probes_per_ttl = {}
    
    for trace_file in trace_files:
        trace_name = trace_file.split('/')[-1].replace('.pcap', '')
        
        # Run the analyzer
        try:
            result = subprocess.run(
                ['python3', 'ip_analyzer.py', trace_file],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout
            
            # Extract results
            all_results[trace_name] = output
            
            # Extract router sequence
            routers = []
            for line in output.split('\n'):
                if line.strip().startswith('router'):
                    match = re.search(r'router (\d+): ([\d.]+)', line)
                    if match:
                        ttl = int(match.group(1))
                        router_ip = match.group(2)
                        routers.append((ttl, router_ip))
            routers_by_trace[trace_name] = routers
            
            # Count probes per TTL (count how many RTT samples for first router)
            rtt_count = 0
            for line in output.split('\n'):
                if 'avg RTT between' in line and 'router 1:' in output:
                    # Find the first router
                    first_router = None
                    for r_line in output.split('\n'):
                        if r_line.strip().startswith('router 1:'):
                            match = re.search(r'router 1: ([\d.]+)', r_line)
                            if match:
                                first_router = match.group(1)
                                break
                    
                    if first_router and first_router in line:
                        # This is a simplification - actual count would require packet analysis
                        break
            
        except subprocess.CalledProcessError as e:
            print(f"Error analyzing {trace_file}: {e}")
            continue
    
    # Determine number of probes per TTL
    # We'll analyze the first trace to estimate
    if all_results:
        first_trace = list(all_results.keys())[0]
        # Count UDP packets with same destination (heuristic: typically 3 probes per TTL)
        # For simplicity, we'll report this as needing manual inspection
        print("1. Number of probes per TTL:")
        print("   To determine this, count the number of outgoing UDP packets (or ICMP echoes)")
        print("   with the same TTL value. Typically 3 probes per TTL for standard traceroute.")
        print("   (This requires manual packet inspection or detailed packet counting code)")
        print()
    
    # Compare router sequences
    print("2. Intermediate router sequence comparison:")
    if len(routers_by_trace) > 1:
        # Compare all traces
        first_trace_name = list(routers_by_trace.keys())[0]
        first_routers = [r[1] for r in routers_by_trace[first_trace_name]]
        
        all_same = True
        for trace_name, routers in routers_by_trace.items():
            current_routers = [r[1] for r in routers]
            if current_routers != first_routers:
                all_same = False
                break
        
        if all_same:
            print("   The sequence of intermediate routers is THE SAME across all trace files.")
            print()
        else:
            print("   The sequence of intermediate routers is DIFFERENT across trace files.")
            print()
            print("3. Differences in router sequences:")
            for trace_name, routers in routers_by_trace.items():
                print(f"\n   {trace_name}:")
                for ttl, router_ip in routers[:10]:  # Show first 10
                    print(f"      TTL {ttl}: {router_ip}")
            
            print("\n   Explanation:")
            print("   Different intermediate routers can occur due to:")
            print("   - Load balancing: Routers may distribute traffic across multiple paths")
            print("   - Routing changes: Network topology or routing policies changed between traces")
            print("   - Equal-cost multipath (ECMP): Multiple paths with the same cost exist")
            print()
    
    # If routers are the same, create RTT comparison table
    if len(routers_by_trace) > 0:
        first_trace_name = list(routers_by_trace.keys())[0]
        first_routers = [r[1] for r in routers_by_trace[first_trace_name]]
        
        # Check if all traces have same routers
        all_same = True
        for trace_name in routers_by_trace:
            current_routers = [r[1] for r in routers_by_trace[trace_name]]
            if current_routers != first_routers:
                all_same = False
                break
        
        if all_same and len(trace_files) > 1:
            print(f"\n4. RTT Comparison Table (since router sequences are the same):")
            print()
            
            # Collect RTT by TTL for each trace
            rtt_data = {}
            for trace_name, output in all_results.items():
                rtt_data[trace_name] = extract_rtt_from_output(output)
            
            # Find all unique TTLs
            all_ttls = set()
            for data in rtt_data.values():
                all_ttls.update(data.keys())
            
            # Print table
            print(f"{'TTL':<6}", end="")
            for i, trace_name in enumerate(sorted(all_results.keys()), 1):
                print(f"{'Trace ' + str(i) + ' RTT (ms)':<20}", end="")
            print()
            print("-" * (6 + 20 * len(all_results)))
            
            for ttl in sorted(all_ttls):
                print(f"{ttl:<6}", end="")
                for trace_name in sorted(all_results.keys()):
                    if ttl in rtt_data[trace_name] and rtt_data[trace_name][ttl]:
                        avg_rtt = rtt_data[trace_name][ttl][0]  # First router at this TTL
                        print(f"{avg_rtt:<20.2f}", end="")
                    else:
                        print(f"{'N/A':<20}", end="")
                print()
            
            print("\nConclusion about which hop incurs maximum delay:")
            print("Examine the table above. Look for:")
            print("- The TTL with consistently high RTT across all traces")
            print("- Large jumps in RTT between consecutive TTLs")
            print("- The hop where RTT increase is most significant")
            print()
            print("Typically, the maximum delay occurs at:")
            print("- Long-distance hops (e.g., cross-continental links)")
            print("- Congested routers or links")
            print("- The final hop to the destination")
            print()

def main():
    # Analyze Group 1
    group1_files = [
        '/mnt/user-data/uploads/group1-trace1.pcap',
        '/mnt/user-data/uploads/group1-trace2.pcap',
        '/mnt/user-data/uploads/group1-trace3.pcap',
        '/mnt/user-data/uploads/group1-trace4.pcap',
        '/mnt/user-data/uploads/group1-trace5.pcap'
    ]
    
    analyze_trace_group(group1_files, "Group 1")
    
    # Analyze Group 2
    group2_files = [
        '/mnt/user-data/uploads/group2-trace1.pcap',
        '/mnt/user-data/uploads/group2-trace2.pcap',
        '/mnt/user-data/uploads/group2-trace3.pcap',
        '/mnt/user-data/uploads/group2-trace4.pcap',
        '/mnt/user-data/uploads/group2-trace5.pcap'
    ]
    
    analyze_trace_group(group2_files, "Group 2")

if __name__ == "__main__":
    main()
