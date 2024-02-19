import json
import subprocess
import os
import time

t1 = time.time()
p = subprocess.Popen("./build/test_offline_process", shell=True)
pipe_path = "/tmp/pcap_fifo"

while not os.path.exists(pipe_path):
    pass

with open(pipe_path, "r") as fifo_file:
    data_str = fifo_file.read()

data = json.loads(data_str)
t2 = time.time()
print("time of parsing: {}s".format(t2 - t1))

print(len(data['ret_arr']))
print(data['ret_arr'][0])
p.wait()