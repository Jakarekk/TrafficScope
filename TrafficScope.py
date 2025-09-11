from readchar import readchar

import capture
import basic_stats
import arp_check


print("1. List of all packets")
print("2. How many packets")
print("3. How many particular packets")
print("4. ARP DATABASE")
print("5. ARP response without request")
print("6. ARP address mac change")
print("7. Show all ... packets")
print("8. Latency")


base = capture.capture_to_base()
arp_database = None

while True:
   
    x = readchar()

    if x == '1':
        print(base)

    elif x == '2':
        basic_stats.count_all_packets(base)
        
    elif x == '3':
        basic_stats.count_packets_by_protocol(base)
        
    elif x == '4':
        arp_database = arp_check.extract_arp_data(base)
        print(arp_database)
   
    elif x == '5':
        arp_check.check_for_unsolicited_arp(arp_database)
   

    elif x == '6':
        arp_check.detect_arp_spoofing(arp_database)
    
    elif x == '7':
        y = input("Which packet?").upper()
        basic_stats.show_packets(base, y)

    elif x == '8':
        basic_stats.latencies(base)
    



    #meninthemiddle dns, arp, ttl, https/http?