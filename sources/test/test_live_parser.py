import json
import subprocess
import os
import time

def process_pcap(th_id):
    start_time = time.time()

    pipe_name = "/tmp/live_read{}".format(th_id)
    os.mkfifo(pipe_name)
    cmd = ["/home/nxg01813/Code/lucid-ddos/sources/preprocess/build/live_parser", "ens160", "10", "0", pipe_name]
    p = subprocess.Popen(cmd, shell=False)
    with open(pipe_name, "r") as fifo_file:
        data_str = fifo_file.read()

    data = json.loads(data_str)
    p.wait()
    os.remove(pipe_name)

    print(len(data["ret_arr"]))

    for pkt in data["ret_arr"]:
        print(pkt)
        break
    
    print('Completed capture in {} seconds.'.format(time.time() - start_time))


process_pcap(0)