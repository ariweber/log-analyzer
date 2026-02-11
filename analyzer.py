def extract_external_ips(log_data):
    external_ips = []
    for log in log_data:
        ip = log[1]
        if not ip.startswith('10.') and not ip.startswith('192.168.'):
            external_ips.append(ip)
    return external_ips

    

    