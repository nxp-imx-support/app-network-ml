import pyshark
import time
from collections import OrderedDict

def process_pcap(pcap_file):
    start_time = time.time()

    pcap_name = pcap_file.split("/")[-1]
    print("Processing file: ", pcap_name)

    cap = pyshark.FileCapture(pcap_file)
    for i, pkt in enumerate(cap):
        # if i % 1000 == 0:
        #     print(pcap_name + " packet #", i)

        # start_time_window is used to group packets/flows captured in a time-window
        # if start_time_window == -1 or float(pkt.sniff_timestamp) > start_time_window + time_window:
        #     start_time_window = float(pkt.sniff_timestamp)

        # pf = parse_packet(pkt)
        # store_packet(pf, temp_dict, start_time_window, max_flow_len)
        # if max_flows > 0 and len(temp_dict) >= max_flows:
        #     break
        pass

    # apply_labels(temp_dict, labelled_flows, in_labels, traffic_type)
    print('Completed file {} in {} seconds.'.format(pcap_name, time.time() - start_time))

if __name__ == '__main__':
    process_pcap("/home/nxg01813/Code/lucid-ddos/sample-dataset/CIC-DDoS-2019-Benign.pcap")