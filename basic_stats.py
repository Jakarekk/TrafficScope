import os
from collections import Counter


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