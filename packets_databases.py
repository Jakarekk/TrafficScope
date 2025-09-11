from collections import defaultdict

def extract_icmp_data(captured_packets):
    databaseICMP = defaultdict(list)
    
    try:
        for packet in captured_packets:
            if 'ICMP' in packet['protocol']: 
          
                databaseICMP['type'].append(packet['type'].split(' ')[0])
                databaseICMP['timestamp'].append(packet['timestamp'])
                if 'sequence_number' in packet:
                    databaseICMP['sequence_number'].append(packet['sequence_number'])
                    databaseICMP['identifier'].append(packet['identifier'])
                else:
                    databaseICMP['sequence_number'].append(None)
                    databaseICMP['identifier'].append(None)
       
    except Exception as e:
        print(f"\nError??: {e}")

    return databaseICMP