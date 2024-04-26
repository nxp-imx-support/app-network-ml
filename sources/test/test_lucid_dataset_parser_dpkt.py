import sys
sys.path.append("..")
from lucid_dataset_parser_dpkt import process_pcap

def test_process_pcap():
    debug_fd = open("./tmp.log", "w")
    flow_list = dict()
    log_list = list()
    process_pcap("/home/nxg01813/Datasets/CICDDoS2019/03-11/SAT-03-11-2018_0100.pcap", flow_list, log_list)
    for row in log_list:
        debug_fd.write(row + "\n")
    for k, v in flow_list.items():
        debug_fd.write(str(v) + "\n")
    debug_fd.close()

if __name__ == '__main__':
    test_process_pcap()