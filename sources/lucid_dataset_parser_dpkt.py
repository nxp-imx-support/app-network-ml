import dpkt
import sys
import time
import socket
import pickle
import random
import hashlib
import argparse
import ipaddress
from sklearn.feature_extraction.text import CountVectorizer
from multiprocessing import Manager, Pool
from util_functions import *
import os
import subprocess
import json
from enum import IntEnum

IDS2018_DDOS_FLOWS = {'attackers': ['18.218.115.60', '18.219.9.1','18.219.32.43','18.218.55.126','52.14.136.135','18.219.5.43','18.216.200.189','18.218.229.235','18.218.11.51','18.216.24.42'],
                      'victims': ['18.218.83.150','172.31.69.28']}

IDS2017_DDOS_FLOWS = {'attackers': ['172.16.0.1'],
                      'victims': ['192.168.10.50']}

CUSTOM_DDOS_SYN = {'attackers': ['11.0.0.' + str(x) for x in range(1,255)],
                      'victims': ['10.42.0.2']}

DOS2019_FLOWS = {'attackers': ['172.16.0.5'], 'victims': ['192.168.50.1', '192.168.50.4']}

DDOS_ATTACK_SPECS = {
    'DOS2017' : IDS2017_DDOS_FLOWS,
    'DOS2018' : IDS2018_DDOS_FLOWS,
    'SYN2020' : CUSTOM_DDOS_SYN,
    'DOS2019': DOS2019_FLOWS
}

class FeatureList(IntEnum):
    sniff_time = 0
    packet_length = 1
    highest_layer = 2
    ip_flags = 3
    protocols_stack = 4
    tcp_len = 5
    tcp_ack = 6
    tcp_flags = 7
    tcp_win = 8
    udp_len = 9
    icmp_type = 10


class TrafficFlowKey(object):
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str):
        super().__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

    def __str__(self) -> str:
        ret_str = "TrafficFlowKey object <"
        ret_str += "src ip:{}, dst ip:{}, src port:{}, dst porot:{}>".format(self.src_ip, self.dst_ip, self.src_port, self.dst_port)
        return ret_str

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        cond1 = self.src_ip == other.src_ip
        cond2 = self.dst_ip == other.dst_ip
        cond3 = self.src_port == other.src_port
        cond4 = self.dst_port == other.dst_port
        cond5 = self.proto == other.proto
        return cond1 and cond2 and cond3 and cond4 and cond5

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    # merge fwd and bwd
    def order_ports(self):
        if self.src_port < self.dst_port:
            tmp = self.src_ip
            self.src_ip = self.dst_ip
            self.dst_ip = tmp

            tmp = self.src_port
            self.src_port = self.dst_port
            self.dst_port = tmp


class TrafficFlow(object):
    def __init__(self, tfkey: TrafficFlowKey):
        super().__init__()
        self.tfkey = tfkey
        self.pkt_cnt = 0
        self.pkt_list = list()

    def __str__(self) -> str:
        ret = str(self.tfkey) + " packets count: {}".format(len(self.pkt_list)) + "\n"
        ret += str(self.pkt_list)
        return ret

    def add_pkt_features(self, pkt_features):
        self.pkt_list.append(pkt_features)
        self.pkt_cnt += 1


class TrafficWin(object):
    def __init__(self, start_time, label):
        self.start_time = start_time
        self.label = label
        self.pf_list = list()


def get_highest_layer_udp(udp_data):
    if isinstance(udp_data, dpkt.dns.DNS):
        return "dns"
    if isinstance(udp_data, dpkt.ntp.NTP):
        return "ntp"
    if isinstance(udp_data, dpkt.netbios.NS):
        return "netbios"
    return "udp"

def get_highest_layer_tcp(tcp_data):
    if isinstance(tcp_data, dpkt.ssl.TLS):
        return "tls"
    if isinstance(tcp_data, dpkt.netbios.NS):
        return "netbios"
    return "tcp"


def process_pcap(pcap_file, flow_list, log_list):
    pcap_fd = open(pcap_file, "rb")
    file_basename = os.path.basename(pcap_file)
    magic_head = pcap_fd.read(4)
    pcap_fd.seek(0)

    pcap_reader = None
    if magic_head == b'\n\r\r\n':
        pcap_reader = dpkt.pcapng.Reader(pcap_fd)
    elif magic_head == b'\xd4\xc3\xb2\xa1':
        pcap_reader = dpkt.pcap.Reader(pcap_fd)
    else:
        print("[DEBUG in PcapUtils] It is not a pcap or pcapng file.")
        print("Magic Header: {}".format(magic_head.hex()))
        return None
    
    pkt_num = 1
    for ts, buf in pcap_reader:
        eth = dpkt.ethernet.Ethernet(buf)
        pkt_features = [0] * 11
        pkt_features[FeatureList.sniff_time] = float(ts)
        pkt_features[FeatureList.packet_length] = len(buf)
        ip_layer = None
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip_layer = eth.data
        else:
            log_list.append("{}: pkt #{} dont have a ip layer.".format(file_basename, pkt_num))
            continue

        tfkey = TrafficFlowKey("", "", 0, 0, 0)
        
        tfkey.src_ip = str(ipaddress.ip_address(ip_layer.src))
        tfkey.dst_ip = str(ipaddress.ip_address(ip_layer.dst))

        udp = None
        tcp = None
        highest_layer = "ip"

        if isinstance(ip_layer, dpkt.ip.IP):
            pkt_features[FeatureList.ip_flags] = ip_layer._flags_offset >> 13
        elif isinstance(ip_layer, dpkt.ip.IP6):
            highest_layer = "ipv6"
        
        # UDP
        if isinstance(ip_layer.data, dpkt.udp.UDP):
            tfkey.proto = dpkt.ip.IP_PROTO_UDP
            udp = ip_layer.data
            tfkey.src_port = udp.sport
            tfkey.dst_port = udp.dport
            highest_layer = get_highest_layer_udp(udp.data)
        # TCP
        elif isinstance(ip_layer.data, dpkt.tcp.TCP):
            tfkey.proto = dpkt.ip.IP_PROTO_TCP
            tcp = ip_layer.data
            tfkey.src_port = tcp.sport
            tfkey.dst_port = tcp.dport
            highest_layer = get_highest_layer_tcp(tcp.data)
        # ICMP
        elif isinstance(ip_layer.data, dpkt.icmp.ICMP):
            highest_layer = "icmp"
            icmp = ip_layer.data
            pkt_features[FeatureList.icmp_type] = icmp.type
        # ICMPv6
        elif isinstance(ip_layer.data, dpkt.icmp6.ICMP6):
            highest_layer = "icmp6"
            icmp6 = ip_layer.data
            pkt_features[FeatureList.icmp_type] = icmp6.type

        # other
        else:
            log_list.append("other protocol, #{}".format(pkt_num))
        
        pkt_features[FeatureList.highest_layer] = int(hashlib.sha256(highest_layer.encode('utf-8')).hexdigest(), 16) % 10 ** 8

        # if pkt_num > 26123:
        #     break
        pkt_num += 1

        tfkey.order_ports()
        if tfkey.src_port == 0 or tfkey.dst_port == 137:
            continue

        if flow_list is not None:
            if tfkey not in flow_list.keys():
                flow_list[tfkey] = TrafficFlow(tfkey)
            flow_list[tfkey].add_pkt_features(pkt_features)

        # limit packets num
        # if max_sample > 0 and pkt_cnt >= max_sample:
        #     break


def extract_pcaps(dataset_folder, output_folder, traffic_type, dataset_type):
    print(dataset_folder, output_folder, traffic_type, dataset_type)
    extract_log_fd = open(os.path.join(output_folder, "extract_pcaps.log"), "a")

    # elements type: {TrafficKey: TrafficFlow}
    flow_dict = Manager().dict()
    log_list = Manager().list()
    pro_pool = Pool(3)


    for row in log_list:
        extract_log_fd.write(row + "\n")
    extract_log_fd.close()
    return


def preprocess_data():
    pass


def main():

    help_string = 'Usage[0]: python3 lucid_dataset_parser.py --dataset_type <dataset_name> --dataset_folder <folder path> --dataset_id <dataset identifier> --packets_per_flow <n> --time_window <t>\n' \
                  'Usage[1]: python3 lucid_dataset_parser.py --preprocess_folder <folder path>'

    parser = argparse.ArgumentParser(
        description='Dataset parser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dataset_folder', nargs='+', type=str,
                        help='Folder with the dataset')
    parser.add_argument('-o', '--output_folder', nargs='+', type=str,
                        help='Output folder')
    parser.add_argument('-f', '--traffic_type', default='all', nargs='+', type=str,
                        help='Type of flow to process (all, benign, ddos)')
    parser.add_argument('-p', '--preprocess_folder', nargs='+', type=str,
                        help='Folder with preprocessed data')
    parser.add_argument('--preprocess_file', nargs='+', type=str,
                        help='File with preprocessed data')
    parser.add_argument('-b', '--balance_folder', nargs='+', type=str,
                        help='Folder where balancing datasets')
    parser.add_argument('-n', '--packets_per_flow', nargs='+', type=str,
                        help='Packet per flow sample')
    parser.add_argument('-s', '--samples', default=float('inf'), type=int,
                        help='Number of training samples in the reduced output')
    parser.add_argument('-i', '--dataset_id', nargs='+', type=str,
                        help='String to append to the names of output files')
    parser.add_argument('-m', '--max_flows', default=0, type=int,
                        help='Max number of flows to extract from the pcap files')
    parser.add_argument('-l', '--label', default=1, type=int,
                        help='Label assigned to the DDoS class')

    parser.add_argument('-t', '--dataset_type', nargs='+', type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019, SYN2020')

    parser.add_argument('-w', '--time_window', nargs='+', type=str,
                        help='Length of the time window')

    parser.add_argument('--no_split', help='Do not split the dataset', action='store_true')

    args = parser.parse_args()

    if args.packets_per_flow is not None:
        max_flow_len = int(args.packets_per_flow[0])
    else:
        max_flow_len = MAX_FLOW_LEN

    if args.time_window is not None:
        time_window = float(args.time_window[0])
    else:
        time_window = TIME_WINDOW

    if args.dataset_id is not None:
        dataset_id = str(args.dataset_id[0])
    else:
        dataset_id = ''

    if args.dataset_type:
        dataset_type = str(args.dataset_type[0])
    else:
        dataset_type = ""

    if args.traffic_type is not None:
        traffic_type = str(args.traffic_type[0])
    else:
        traffic_type = 'all'

    if args.dataset_folder:
        dataset_folder = args.dataset_folder[0]
        if args.output_folder:
            output_folder = args.output_folder[0]
        else:
            output_folder = dataset_folder
        extract_pcaps(dataset_folder, output_folder, traffic_type, dataset_type)

    if args.preprocess_folder:
        pass
    

    if args.dataset_folder is None and args.preprocess_folder is None and args.preprocess_file is None and args.balance_folder is None:
        print (help_string)
    if args.dataset_type is None and args.dataset_folder is not None:
        print("Please specify the dataset type (DOS2017, DOS2018, DOS2020)!")
        print(help_string)
    if args.output_folder is None and args.balance_folder is not None:
        print("Please specify the output folder!")
        print(help_string)

if __name__ == '__main__':
    main()