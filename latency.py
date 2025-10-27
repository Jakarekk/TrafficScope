import numpy as np
import arp_check
import packets_databases


def latencyICMP(captured_packets):
    databaseICMP = packets_databases.extract_icmp_data(captured_packets)
    num_packets = len(databaseICMP['type'])
    pending_requests = []
    request = {
                'request': pending_requests,
                'time': []
              }
    latency = []
    response_time = []
    request_time = []
    
    
    for i in range(num_packets):
        
        type1 = databaseICMP['type'][i]
        identifier = databaseICMP["identifier"][i]
        sequence_number = databaseICMP["sequence_number"][i]
        time = databaseICMP['timestamp'][i]

        if type1 == '8':
            temp = [identifier, sequence_number]
            if temp not in pending_requests:
                pending_requests.append(temp)
                request['time'].append(time)
        elif type1 == '0':
            temp = [identifier, sequence_number]
            if temp in pending_requests:
                a = pending_requests.index(temp)
                        
                response_time = time
                request_time = request['time'][a]
                result = response_time - request_time
                latency.append(result)
                outcome = latency_ms(latency)
                pending_requests.remove(temp)

    return outcome



def latencyDNS(captured_packets):
    databaseDNS = packets_databases.extract_dns_data(captured_packets)
    latency = []
    pending_request = {}


    for i in range(len(databaseDNS['id'])):
        if databaseDNS['is_response'][i] == 'False':
            pending_request[databaseDNS['id'][i]] = databaseDNS['timestamp'][i]
        elif databaseDNS['is_response'][i] == 'True' :
            if databaseDNS['id'][i] in pending_request:
                response_time = databaseDNS['timestamp'][i]
                request_time = pending_request[databaseDNS['id'][i]]
                result = response_time - request_time
                latency.append(latency_ms([result]))
                del pending_request[databaseDNS['id'][i]]
        
    
    return latency




def latencyARP(captured_packets):
    databaseARP = arp_check.extract_arp_data(captured_packets)
    num_packets = len(databaseARP['Operation'])
    pending_requests = []
    request = {
                'request': pending_requests,
                'time': []
              }
    latency = []
  
    for i in range(num_packets):
        
        operation = databaseARP['Operation'][i]
        sender_ip = databaseARP["Sender's IP"][i]
        target_ip = databaseARP["Target's IP"][i]
        time = databaseARP['Timestamp'][i]
        
        if operation == '1': 
                     
            if (sender_ip, target_ip) not in pending_requests:
                pending_requests.append((sender_ip, target_ip))
                request['time'].append(time)



        elif operation == '2': 
               corresponding_request = (target_ip, sender_ip)

               if corresponding_request in pending_requests:
                    a = pending_requests.index(corresponding_request)
                        
                    response_time = time
                    request_time = request['time'][a]
                    result = response_time - request_time
                    latency.append(result)
                    outcome = latency_ms(latency)
                    pending_requests.remove(corresponding_request)
    return outcome



def latency_ms(latency):
    latencies_in_ms = [l.total_seconds() * 1000 for l in latency]
    return latencies_in_ms
   


def statistic(result):
    #print(result)
    
    print(f"Avarage: {np.mean(result)}")
    print(f"Max: {np.max(result)}")
    print(f"Min: {np.min(result)}")
    print(f"Median: {np.median(result)}")
    print(f"Standard deviation: {np.std(result)}")


    
