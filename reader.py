import csv
def read_log(log_file):
    with open(log_file, 'r') as f:
        return [row for row in csv.reader(f)]
    
