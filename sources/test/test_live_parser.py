import json
import subprocess
import os
import time

def process_pcap():
    start_time = time.time()

    pipe_name = "/tmp/live_read"
    # if os.path.exists(pipe_name):
    #     os.remove(pipe_name)
    # os.mkfifo(pipe_name)
    # os.chmod(pipe_name, 0o666)
    cmd = ["sudo", "/home/nxg01813/Code/lucid-ddos/sources/preprocess/build/live_parser", "ens160", "10", "0", pipe_name]
    p = subprocess.Popen(cmd, shell=False)
    with open(pipe_name, "r") as fifo_file:
        data_str = fifo_file.read()

    data = json.loads(data_str)
    p.wait()
    # os.remove(pipe_name)

    print(len(data["ret_arr"]))

    for pkt in data["ret_arr"]:
        print(pkt)
        break
    
    print('Completed capture in {} seconds.'.format(time.time() - start_time))


process_pcap()