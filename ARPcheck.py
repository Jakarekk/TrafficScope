import os
from collections import defaultdict
import pandas as pd
import time

import FileAnalyse



pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', None) 




def ARPdata(capture):

    databaseARP = defaultdict(list)

    timer1 = time.perf_counter()
    timer2 = 0.0
    interval = 1.0
    founds = 0
    alert = False

    try:
        packet_counter = 0
        timer2 = time.perf_counter()
        for packet in capture:
            packet_counter += 1
            if 'ARP' in packet: 
                founds += 1
            
                databaseARP['Operation'].append(packet.arp.opcode) 
                databaseARP['Sender\'s IP'].append(packet.arp.src_proto_ipv4) 
                databaseARP['Sender\'s MAC'].append(packet.arp.src_hw_mac) 
                databaseARP['Target\'s IP'].append(packet.arp.dst_proto_ipv4) 
                databaseARP['Target\'s MAC'].append(packet.arp.dst_hw_mac)
                if packet.arp.src_proto_ipv4 == packet.arp.dst_proto_ipv4:
                    databaseARP['Gratitious?'].append('1')
                else:
                    databaseARP['Gratitious?'].append('0')
            if timer2 - timer1 >= interval:
                   
                    if (founds > 50 and founds < 200):
                        print("There's a possible issue. Alarming amount of ARP packets")
                        alert = True
                    elif founds > 200:
                        print("The device is probalby being attacked")
                        alert = True
                        founds = 0
                        timer1 = time.perf_counter()

        if alert == False:
             print("The amount of ARP packets is normal")

    except Exception as e:
        print(f"\nError??: {e}")
    

    df = pd.DataFrame(databaseARP)
    df.index = df.index + 1

    #print(df)

    return databaseARP
    


def GratitiousFrequency(arp_database):
  
    if not arp_database['Operation']:
        print("No packets")
        return

    num_packets = len(arp_database['Operation'])

    pending_requests = []

    for i in range(num_packets):
        
        operation = arp_database['Operation'][i]
        sender_ip = arp_database["Sender's IP"][i]
        target_ip = arp_database["Target's IP"][i]
        is_gratuitous = arp_database['Gratitious?'][i]

        if operation == '1': 
            #print(f"Index {i+1}: Request from {sender_ip} to {target_ip}")
            if (sender_ip, target_ip) not in pending_requests:
                pending_requests.append( (sender_ip, target_ip) )

        elif operation == '2': 
            #print(f"Index {i+1}: Response from {sender_ip} (to: {target_ip})")
            corresponding_request = (target_ip, sender_ip)

            if corresponding_request in pending_requests:
                pending_requests.remove(corresponding_request)

            else:
                if is_gratuitous == '1':
                     print(f"Index {i+1}: Gratuitous ARP from {sender_ip}.")
                else:
                     print(f"Index {i+1}: THE RESPONSE WITHOUT REQUEST FROM {sender_ip} TO {target_ip}!")
    #print(pending_requests)
    

def FalseARP(arp_database):

    if not arp_database.get('Operation'):
        print("No packets")
        return

    num_packets = len(arp_database['Operation'])

    ip_to_mac = {}

    for i in range(num_packets):
        operation = arp_database['Operation'][i]
        sender_ip = arp_database["Sender's IP"][i]
        sender_mac = arp_database["Sender's MAC"][i]

       
        if operation == '2':
            
            if sender_ip in ip_to_mac:

                if ip_to_mac[sender_ip] != sender_mac:
                    print("ADDRESS MAC HAS CHANGED")
                    print(f"IP: {sender_ip}")
                    print(f"Previous MAC: {ip_to_mac[sender_ip]}")
                    print(f"New MAC: {sender_mac}")
                    
            else:
               
                ip_to_mac[sender_ip] = sender_mac







