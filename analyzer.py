def extract_ips(log_data):
    external_ips = []
    for log in log_data:
        ip = log[1]
        if not ip.startswith('10.') and not ip.startswith('192.168.'):
            external_ips.append(ip)
    return external_ips


def sensitive_ports(log_data):
    list_ensitive_ports = [log for log in log_data if log[3] == "3389" or log[3] == "22" or log[3] == "23"]
    return list_ensitive_ports







    


    

    

    