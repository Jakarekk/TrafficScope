import os
from collections import Counter


def count_all_packets(file, capture):

    packet_counter = 0

    for packet in capture:
        packet_counter +=1

    print(f"Found {packet_counter} packets")


def count_packets_by_protocol(file, capture):

    protocol_counter = Counter()
   
    for packet in capture:
      
        protocol_names = packet.highest_layer
        protocol_counter[protocol_names] += 1
       
    for protocol, count in protocol_counter.items():
        print(f"Found protocol (the highest): '{protocol.upper()}': {count} times")