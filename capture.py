import pyshark

import file_analyse

captured_packets = []

def capture_to_base():

    file = r"ping.pcapng" 
    capture = pyshark.FileCapture(file)
   

    for i, packet in enumerate(capture):
   
        packet_info = {
            'packet_number': i + 1,
            'timestamp': packet.sniff_time,
            'length': packet.length
        }


        if 'ARP' in packet:
            arp_details = file_analyse.arp(packet)
            packet_info.update(arp_details)
        
        elif 'ICMP' in packet:
            icmp_details = file_analyse.icmp(packet)
            packet_info.update(icmp_details)
        
        elif 'IGMP' in packet:
            igmp_details = file_analyse.igmp(packet)
            packet_info.update(igmp_details)
        
        elif 'TCP' in packet:
            tcp_details = file_analyse.tcp(packet)
            packet_info.update(tcp_details)
        
        elif 'UDP' in packet:
            udp_details = file_analyse.udp(packet)
            packet_info.update(udp_details)
   
    
        else:
      
            packet_info['protocol'] = packet.highest_layer

        captured_packets.append(packet_info)


    capture.close()

    return captured_packets

