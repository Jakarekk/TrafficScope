import os




def AnalyseFile(file, capture):

    
    print(f"Checking the file: {file}")

    if not os.path.exists(file):
        print("Error: Theres no file there!")
    else:
        print("We have the file")
        try:
          
        
            packet_counter = 0

            print("Just a basic WHATS IN MY FILE!!??")
            for packet in capture:
                packet_counter += 1
                print(f"Packet nr {packet_counter}: {packet.highest_layer}")
                if 'ARP' in packet:
                    ARP(packet)
                elif 'ICMP' in packet:
                     ICMP(packet)
                elif 'ETH' in packet:
                     ETH(packet)

                elif 'TCP' in packet:
                     if packet.highest_layer == 'TLS':
                        print("TLS (over TCP)")
                        TCP(packet)
                     
                     elif packet.highest_layer == 'DATA':
                        print( "Unknown data - DATA")
                        TCP(packet)
                     else:
                         TCP(packet)

                elif 'IGMP' in packet:
                     IGMP(packet)
                elif 'UDP' in packet:
                     UDP(packet)
                elif 'DNS' in packet:
                     GenericProtocolAnalyser(packet, 'DNS')
                elif 'NBNS' in packet:
                     GenericProtocolAnalyser(packet, 'NBNS')
                elif 'MDNS' in packet:
                     GenericProtocolAnalyser(packet, 'MDNS')
                elif 'LMNR' in packet:
                     GenericProtocolAnalyser(packet, 'LMNR')

                
                

                else:    print("!!!!!!!!!!!!!!!!!!!We dont have that YET!!!!!!!!!!!!!!!!!!!")

            if packet_counter == 0:
                print("\nNo more packets.")
           

        except Exception as e:
            print(f"\nError??: {e}")



def ARP(packet):
    print(f"\t Operation: {packet.arp.opcode} {'Request' if packet.arp.opcode == '1' else 'Reply' if packet.arp.opcode == '2' else 'We dont have that operation yet' } \n ")
    print(f"\t Sender's MAC: {packet.arp.src_hw_mac}")
    print(f"\t Sender's IP: {packet.arp.src_proto_ipv4} \n")

    print(f"\t Targets's MAC: {packet.arp.dst_hw_mac}")
    print(f"\t Targets's IP: {packet.arp.dst_proto_ipv4} \n")

    if packet.arp.src_proto_ipv4 == packet.arp.dst_proto_ipv4:
        print("IT IS GRATITIOUS!")
    


def ICMP(packet):
    
    Type_map = {
       "3" : "Destination unreachable",
       "4" : "Source quench",
       "11" : "Time Exceeded",
       "12" : "Parametr problem",
       "8" : "Echo request",
       "0" : "Echo reply"
       }

    Code = {
        "3" : {"0" : "Net is unreachable",
               "1" : "Host is unreachable",
               "2" : "Protocol is unreachable",
               "3" : "Port is unreachable"},
        "5" : {"0" : "Redirect datagram for the network",
               "1" : "Redirect datagram for the host",
               "2" : "Redirect datagram for the type of service and network",
               "3" : "Redirect datagram for the type of service and host"},
        "11" : {"0" : "Time to Live exceeded in transit",
               "1" : "Fragment reassembly time exceeded"},
        "12" : {"0" : "Pointer indicates the error",
               "1" : "Missing a required option",
               "2" : "Bad length"},
        "8"  : {"0": "Echo request"},
        "0"  : {"0": "Echo reply"}

        }

    type_desc = Type_map.get(packet.icmp.type, "Unknown type")
    
    code_desc = Code.get(packet.icmp.type, {}).get(packet.icmp.code, "No description for the code")

    print(f"\t Type: {packet.icmp.type} :  {type_desc}")
    print(f"\t Code: {packet.icmp.code} : {code_desc}")
    print(f"\t Checksum status: {packet.icmp.checksum_status}")
    if hasattr(packet, 'icmp'):
        if hasattr(packet.icmp ,'ident'):
            print(f"\t Identifier: {packet.icmp.ident} Sequence number: {packet.icmp.seq}")

def IGMP(packet):
        x = packet.igmp.type
        if x == '0x11':
            y = 'Membership Query'
        elif x in ['0x12','0x16','0x22']:
            y = 'Membership Report'
        elif x == '0x17':
            y = 'Leave group'
        else: 
            y = 'We dont have that yet'
        print(f"\t Type: {packet.igmp.type} : {y}")
        print(f"\t Checksum Status: {packet.igmp.checksum_status}")
        print(f"\t Multicast address: {packet.igmp.maddr}")
       
        

def TCP(packet):
    
    print(f"\t Source port: {packet.tcp.srcport}")
    print(f"\t Destination port: {packet.tcp.dstport}")
    print(f"\t Flags: {packet.tcp.flags.showname}")
    
    

def UDP(packet):
    print(f"\t Source port: {packet.udp.srcport}")
    print(f"\t Destination port: {packet.udp.dstport}")
    print(f"\t Length: {packet.udp.length}")
    print(f"\t  {packet.udp.checksum_status.showname}")


def ETH(packet):
    print(f"Type: {packet.eth.type}")


def GenericProtocolAnalyser(packet, name):
    proto_layer = packet[name.lower()]
    
    print(f"\t ID: {proto_layer.id}")
    print(f"\t Flags: {proto_layer.flags.showname}")
    print(f"\t Queries count: {proto_layer.count_queries}")
    print(f"\t Answers count: {proto_layer.count_answers}")
    










    
