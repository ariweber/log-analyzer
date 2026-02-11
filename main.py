from reader import read_log
from checks import get_hours

log_data = read_log("network_traffic.log")

a = get_hours(log_data)
print(a)



