import json
import subprocess
import os
import time

def process_pcap(pcap_file, th_id):
    start_time = time.time()

    pcap_name = pcap_file.split("/")[-1]
    print("Processing file: ", pcap_name)

    pipe_name = "/tmp/pcap_read{}".format(th_id)
    os.mkfifo(pipe_name)
    cmd = ["/home/nxg01813/Code/lucid-ddos/sources/preprocess/build/pcap_parser", pcap_file, pipe_name]
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
    
    print('Completed file {} in {} seconds.'.format(pcap_name, time.time() - start_time))


process_pcap("/home/nxg01813/Code/lucid-ddos/sample-dataset/CIC-DDoS-2019-Benign.pcap", 0)