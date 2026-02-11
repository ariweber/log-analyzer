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

def log_size_labeling(log_data):
    for log in log_data:
        if int(log[5]) >5000:
            log.append("LARG")
        else:
            log.append("NORMAL")
    return log_data    


def ips(log_data):
    list_ip = [log[1] for log in log_data]
    return list_ip

def ip_dictionary(log_data):
    ip_data = ips(log_data)
    dict_ip = {ip: ip_data.count(ip) for ip in set(ip_data)}
    return dict_ip






    


    

    

    