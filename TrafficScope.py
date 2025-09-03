import pyshark
from readchar import readchar

import FileAnalyse
import BasicStats
import ARPcheck

#Temporarly theres a static reference
file = r"ping.pcapng" 


print("Choose: \n 1.WHAT'S IN MY FILE?! \n 2.How many packets? \n 3.How many specific packets we have \n 4.ARP check")


while True:
    capture = pyshark.FileCapture(file)
    x = readchar()
    if x == '1':
        FileAnalyse.AnalyseFile(file, capture)
    elif x == '2':
        BasicStats.HowMany(file, capture)
    elif x == '3':
        BasicStats.HowManySpecific(file, capture)
    elif x == '4':
        ARPdict = ARPcheck.ARPdata(capture)
        #print(ARPdict)
        ARPcheck.GratitiousFrequency(ARPdict)
        ARPcheck.FalseARP(ARPdict)
    



    #meninthemiddle dns, arp, ttl, https/http?