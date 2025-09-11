def arp(packet):
    op_code = packet.arp.opcode
    operation_desc = 'Request' if op_code == '1' else 'Reply' if op_code == '2' else 'Unknown operation'
    
    arp_data = {
        'protocol': 'ARP',
        'operation': f"{op_code} ({operation_desc})",
        'sender_mac': packet.arp.src_hw_mac,
        'sender_ip': packet.arp.src_proto_ipv4,
        'target_mac': packet.arp.dst_hw_mac,
        'target_ip': packet.arp.dst_proto_ipv4,
        'gratuitous': packet.arp.src_proto_ipv4 == packet.arp.dst_proto_ipv4,
        'timestamp': packet.sniff_time
    }
    return arp_data

def icmp(packet):
    Type_map = { "3": "Destination unreachable", "4": "Source quench", "11": "Time Exceeded", "12": "Parameter problem", "8": "Echo request", "0": "Echo reply" }
    Code_map = {
        "3": {"0": "Net is unreachable", "1": "Host is unreachable", "2": "Protocol is unreachable", "3": "Port is unreachable"},
        "5": {"0": "Redirect for network", "1": "Redirect for host", "2": "Redirect for type of service and network", "3": "Redirect for type of service and host"},
        "11": {"0": "TTL exceeded", "1": "Fragment reassembly time exceeded"}, "12": {"0": "Pointer indicates error", "1": "Missing required option", "2": "Bad length"},
        "8": {"0": "Echo request"}, "0": {"0": "Echo reply"}
    }
    
    icmp_type = packet.icmp.type
    icmp_code = packet.icmp.code
    
    icmp_data = {
        'protocol': 'ICMP',
        'type': icmp_type,
        'type_description': Type_map.get(icmp_type, "Unknown type"),
        'code': icmp_code,
        'code_description': Code_map.get(icmp_type, {}).get(icmp_code, "No description"),
        'checksum_status': packet.icmp.checksum_status,
        'timestamp': packet.sniff_time
    }
    
    if hasattr(packet.icmp, 'ident'):
        icmp_data['identifier'] = packet.icmp.ident
        icmp_data['sequence_number'] = packet.icmp.seq
        
    return icmp_data

def igmp(packet):
    igmp_type = packet.igmp.type
    if igmp_type == '0x11':
        type_desc = 'Membership Query'
    elif igmp_type in ['0x12','0x16','0x22']:
        type_desc = 'Membership Report'
    elif igmp_type == '0x17':
        type_desc = 'Leave group'
    else: 
        type_desc = 'Unknown type'
        
    igmp_data = {
        'protocol': 'IGMP',
        'type': igmp_type,
        'type_description': type_desc,
        'checksum_status': packet.igmp.checksum_status,
        'multicast_address': packet.igmp.maddr
    }
    return igmp_data
       
def tcp(packet):
    tcp_data = {
        'protocol': 'TCP',
        'src_port': packet.tcp.srcport,
        'dst_port': packet.tcp.dstport,
        'flags': packet.tcp.flags.showname
    }
    return tcp_data
    
def udp(packet):
    udp_data = {
        'protocol': 'UDP',
        'src_port': packet.udp.srcport,
        'dst_port': packet.udp.dstport,
        'length': packet.udp.length,
        'checksum_status': packet.udp.checksum_status.showname
    }
    return udp_data

def eth(packet):
    eth_data = {
        'eth_type': packet.eth.type,
        'src_mac': packet.eth.src,
        'dst_mac': packet.eth.dst
    }
    return eth_data

def generic(packet, name):

    proto_layer = packet[name.lower()]
    generic_data = {
        'protocol': name.upper(),
        'id': proto_layer.id,
        'flags': proto_layer.flags.showname,
        'queries_count': proto_layer.count_queries,
        'answers_count': proto_layer.count_answers
    }
    return generic_data









    
