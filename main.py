from reader import read_log
from checks import dict_port, unusual_hours


log_data = read_log("network_traffic.log")

a = unusual_hours(log_data)
for i in a:
    print (i)
