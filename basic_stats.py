import os
from collections import Counter

import arp_check
import latency


def count_all_packets(captured_packets):

    packet_counter = 0

    for packet in captured_packets:
        packet_counter +=1

    print(f"Found {packet_counter} packets")


def count_packets_by_protocol(captured_packets):

    protocol_counter = Counter()
   
    for packet in captured_packets:
      
        protocol_names = packet['protocol']
        protocol_counter[protocol_names] += 1
       
    for protocol, count in protocol_counter.items():
        print(f"Found protocol (the highest): '{protocol.upper()}': {count} times")

def show_packets(captured_packets, name):
    for packet in captured_packets:
        if name in packet['protocol']:
            print(packet)

def latencies(captured_packets):
    arp = latency.latencyARP(captured_packets)
    print("\n\nARP packet latency statistics:")
    latency.statistic(arp)
    
    dns = latency.latencyDNS(captured_packets)
    print("\n\nDNS packet latency statistics:")
    latency.statistic(dns)
    
    icmp = latency.latencyICMP(captured_packets)
    print("\n\nICMP packet latency statistics:")
    latency.statistic(icmp)

    
       

                
                 

      
          

    
           