import pyshark
from readchar import readchar

import file_analyse
import basic_stats
import arp_check

#Temporarly theres a static reference
file = r"ping.pcapng" 


print("Choose: \n 1.WHAT'S IN MY FILE?! \n 2.How many packets? \n 3.How many specific packets we have \n 4.ARP check")


while True:
    capture = pyshark.FileCapture(file)
    x = readchar()
    if x == '1':
        file_analyse.analyse_file(file, capture)
    elif x == '2':
        basic_stats.count_all_packets(file, capture)
    elif x == '3':
        basic_stats.count_packets_by_protocol(file, capture)
    elif x == '4':
        arp_database = arp_check.extract_arp_data(capture)
        #print(arp_database)
        arp_check.check_for_unsolicited_arp(arp_database)
        arp_check.detect_arp_spoofing(arp_database)
    



    #meninthemiddle dns, arp, ttl, https/http?