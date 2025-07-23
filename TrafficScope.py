import pyshark
from readchar import readchar

import FileAnalyse
import BasicStats

#Temporarly theres a static reference
file = r"ping.pcapng" 
capture = pyshark.FileCapture(file)

print("Choose: \n 1.WHAT'S IN MY FILE?! \n 2.How many packets? \n 3.How many specific packets we have ")
x = readchar()

if x == '1':
    FileAnalyse.AnalyseFile(file, capture)
elif x == '2':
    BasicStats.HowMany(file, capture)
elif x == '3':
    BasicStats.HowManySpecific(file, capture)