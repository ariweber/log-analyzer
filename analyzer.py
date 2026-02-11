def extract_external_ips(log_data):
    external_ips = []
    for log in log_data:
        ip = log[1]
        if not ip.startswith('10.') and not ip.startswith('192.168.'):
            external_ips.append(ip)
    return external_ips


def sensitive_ports(log_data):
    list_ensitive_ports = [port for port in log_data if port[3] == "3389" or port[3] == "22" or port[3] == "23"]
    return list_ensitive_ports

def log_over_5000(log_data):
    list_log_5000 =[log for log in log_data if int(log[5])>5000]
    return list_log_5000
    


    

    

    