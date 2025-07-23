import os
from collections import Counter


def HowMany(file, capture):

    packet_counter = 0

    for packet in capture:
        packet_counter +=1

    print(f"Found {packet_counter} packets")


def HowManySpecific(file, capture):

    protocol_counter = Counter()
   
    for packet in capture:
      
        protocol_names = packet.highest_layer
        protocol_counter[protocol_names] += 1
       
    for protocol, count in protocol_counter.items():
        print(f"Found protocol (the highest): '{protocol.upper()}': {count} times")