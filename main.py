from analyzer import extract_external_ips, sensitive_ports
from reader import read_log


log_data = read_log("network_traffic.log")
ports = sensitive_ports(log_data)
print(ports)





