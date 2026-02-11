from analyzer import extract_ips, sensitive_ports

def log_over_5000(log_data):
    list_log_5000 = [log for log in log_data if int(log[5])>5000]
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

def dict_port(log_data):
    dict_port_protcol = {log[4]: log[3] for log in log_data}
    return dict_port_protcol

def unusual_hours(log_data):
    log_hours = [log for log in log_data if 0 <= int(log[0][11:13]) < 6]
    return log_hours
    

def detect_suspicious_ips(log_data):
    exteranl_ip = extract_ips(log_data)
    sensitive_port = sensitive_ports(log_data)
    larg = log_over_5000(log_data)
    unusual_hour = unusual_hours(log_data)
    pass







