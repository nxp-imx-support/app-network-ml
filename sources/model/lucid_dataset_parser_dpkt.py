# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

# Extract features from pcap file via dpkt.
# The way features are extracted should be same as /preprocess/extract_ptotocols.cpp

import dpkt
import sys
import time
import hashlib
import argparse
import ipaddress
from multiprocessing import Manager, Pool
from util_functions import *
import os
from enum import IntEnum
from sklearn.model_selection import train_test_split
import h5py
import random


DOS2019_FLOWS = {'attackers': ['172.16.0.5'], 'victims': ['192.168.50.1', '192.168.50.4']}

PROSTACK_ETH = 1
PROSTACK_IP = 1 << 1
PROSTACK_TCP = 1 << 2
PROSTACK_UDP = 1 << 3
PROSTACK_ICMP = 1 << 4
PROSTACK_SSL = 1 << 5
PROSTACK_HTTP = 1 << 6
PROSTACK_DNS = 1 << 7

flow_len_threshold = 1
win_time_period = 10
win_max_pkt = 10

feature_value_range = [
    [0, 10],
    [0, 0xFFFF],
    [0, 0x0F],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFFFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFF]
]


class FeatureList(IntEnum):
    sniff_time = 0
    packet_length = 1
    ip_flags = 2
    highest_layer = 3
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
        ret_str += "src ip:{}, dst ip:{}, src port:{}, dst port:{}, proto:{}>".format(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)
        return ret_str

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        cond1 = self.src_ip == other.src_ip
        cond2 = self.dst_ip == other.dst_ip
        cond3 = self.src_port == other.src_port
        cond4 = self.dst_port == other.dst_port
        cond5 = self.proto == other.proto
        cond6 = self.src_ip == other.dst_ip
        cond7 = self.src_port == other.dst_port
        cond8 = self.dst_ip == other.src_ip
        cond9 = self.dst_port == other.src_port
        return cond5 and ((cond1 and cond2 and cond3 and cond4) or (cond6 and cond7 and cond8 and cond9))

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    # unify the direction of bidirectional flow
    def reversal(self):
        ret = TrafficFlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.proto)
        return ret


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


def process_pcap(pcap_file, log_list):
    log_list.append("pcap file: {}".format(pcap_file))
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
    
    # TrafficFlowKey: TrafficFlow
    flow_list = dict()
    pkt_num = 0
    t1 = time.time()
    for ts, buf in pcap_reader:
        # if pkt_num % 1000 == 0:
        #     print("Processing #{}".format(pkt_num))
        eth = dpkt.ethernet.Ethernet(buf)
        pkt_features = [0.0] * 11
        pkt_features[FeatureList.sniff_time] = float(ts)
        pkt_features[FeatureList.packet_length] = len(buf)
        
        ip_layer = None
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_layer = eth.data
        else:
            log_list.append("{}: pkt #{} dont have a ipv4 layer.".format(file_basename, pkt_num))
            continue

        tfkey = TrafficFlowKey("", "", 0, 0, 0)
        
        tfkey.src_ip = str(ipaddress.ip_address(ip_layer.src))
        tfkey.dst_ip = str(ipaddress.ip_address(ip_layer.dst))

        udp = None
        tcp = None
        
        if isinstance(ip_layer, dpkt.ip.IP):
            ip_flags = ip_layer._flags_offset >> 13
            ip_frag_offset = ip_layer._flags_offset & 0x1FFF
            if ip_frag_offset != 0 or ip_flags & 0x1:
                log_list.append("#{}: IP fragments. Skip.".format(pkt_num))
                continue
            pkt_features[FeatureList.ip_flags] = ip_layer._flags_offset >> 13
            pkt_features[FeatureList.highest_layer] = PROSTACK_IP
            pkt_features[FeatureList.protocols_stack] = PROSTACK_ETH + PROSTACK_IP
        # UDP
        if isinstance(ip_layer.data, dpkt.udp.UDP):
            tfkey.proto = dpkt.ip.IP_PROTO_UDP
            udp = ip_layer.data
            tfkey.src_port = udp.sport
            tfkey.dst_port = udp.dport
            pkt_features[FeatureList.highest_layer] = PROSTACK_UDP
            pkt_features[FeatureList.protocols_stack] += PROSTACK_UDP
            pkt_features[FeatureList.udp_len] = udp.ulen
        # TCP
        elif isinstance(ip_layer.data, dpkt.tcp.TCP):
            tfkey.proto = dpkt.ip.IP_PROTO_TCP
            tcp = ip_layer.data
            tfkey.src_port = tcp.sport
            tfkey.dst_port = tcp.dport
            pkt_features[FeatureList.highest_layer] = PROSTACK_TCP
            pkt_features[FeatureList.protocols_stack] += PROSTACK_TCP
            pkt_features[FeatureList.tcp_flags] = tcp.flags
            pkt_features[FeatureList.tcp_ack] = tcp.ack
            pkt_features[FeatureList.tcp_win] = tcp.win
            pkt_features[FeatureList.tcp_len] = len(buf) - 14 - 20 - 20
        # other, it is neither TCP nor UDP.
        else:
            log_list.append("#{}: Neither TCP nor UDP. Unknown protocol.".format(pkt_num))
            continue
        
        # if pkt_num > 26123:
        #     break
        pkt_num += 1
        # Filter NBNS
        if tfkey.src_port == 0 or tfkey.dst_port == 137:
            continue

        if flow_list is not None:
            bwd_tfkey = tfkey.reversal()
            if tfkey in flow_list.keys():
                flow_list[tfkey].add_pkt_features(pkt_features)
            elif bwd_tfkey in flow_list.keys():
                flow_list[bwd_tfkey].add_pkt_features(pkt_features)
            else:
                flow_list[tfkey] = TrafficFlow(tfkey)
            
        
        log_list.append("#{}, ({}, {}, {}, {}, {}):".format(pkt_num, tfkey.src_ip, tfkey.src_port, tfkey.dst_ip, tfkey.dst_port, tfkey.proto))
        log_list.append("{}".format(pkt_features))

    print("pkt_cnt: {}, flow cnt: {}".format(pkt_num, len(flow_list)))
    print("Completed file {} in {:.3f} seconds".format(pcap_file, time.time() - t1))

    # debug
    log_list.append("======={} flow debug==========".format(pcap_file))
    for k in flow_list.keys():
        log_list.append("\"{}\", {}, \"{}\", {}".format(k.src_ip, k.src_port, k.dst_ip, k.dst_port))
    log_list.append("======={} flow debug end=========".format(pcap_file))

    pcap_fd.close()
    return flow_list


def normalize_packet(pkt):
    ret_arr = [0.0] * 11
    for i in range(1, 11):
        ret_arr[i] = 1 - (feature_value_range[i][1] - pkt[i]) / (feature_value_range[i][1] - feature_value_range[i][0])
    return ret_arr


def transfer_to_feature(flow, feature_list):
    pkt_num = flow.pkt_cnt
    pkt_seq = 0
    pkt_idx = 0
    now = 0
    start_ts = flow.pkt_list[0][0]
    diff = 0
    sample_cnt = 0
    time_win = list()
    while pkt_idx < pkt_num:
        # if pkt_idx % 20 == 0:
        #     print("In transfer_to_feature, pkt_idx: {}".format(pkt_idx))
        pkt = flow.pkt_list[pkt_idx]
        now = pkt[0]
        diff = now - start_ts

        # Require a new time window.
        if diff - win_time_period > 1e-6:
            # Padding last window
            while pkt_seq < win_max_pkt:
                time_win.append([0.0] * 11)
                pkt_seq += 1
            feature_list.append(time_win)
            sample_cnt += 1
            # New time window
            time_win = list()
            pkt_seq = 0
            start_ts = pkt[0]
            f_val_arr = normalize_packet(pkt)
            f_val_arr[0] = 0
            pkt_seq += 1
            time_win.append(f_val_arr)
        else:
            if pkt_seq > win_max_pkt - 1:
                pkt_idx += 1
                continue
            f_val_arr = normalize_packet(pkt)
            f_val_arr[0] = diff
            time_win.append(f_val_arr)
            pkt_seq += 1
        pkt_idx += 1

    # padding the last one
    while pkt_seq < win_max_pkt:
        time_win.append([0.0] * 11)
        pkt_seq += 1
    feature_list.append(time_win)
    sample_cnt += 1
    return sample_cnt

def calculate_flow_features(flow_list, feature_list, label_list, label_count, flow_count):
    for f_key, flow in flow_list.items():
        if flow.pkt_cnt < flow_len_threshold:
            continue
        new_samples = transfer_to_feature(flow, feature_list)
        if f_key.src_ip in DOS2019_FLOWS['attackers'] or f_key.dst_ip in DOS2019_FLOWS['attackers']:
            label_list += [1] * new_samples
            label_count[0] += new_samples
            flow_count[0] += 1
        else:
            label_list += [0] * new_samples
            label_count[1] += new_samples
            flow_count[1] += 1
    return


def balance_dataset(feature_list, label_list):
    loop_num = len(label_list)
    i = 0
    ddos_samples = list()
    ddos_cnt = 0
    benign_samples = list()
    benign_cnt = 0
    while i < loop_num:
        if label_list[i] == 0:
            ddos_samples.append(feature_list[i])
            ddos_cnt += 1
        else:
            benign_samples.append(feature_list[i])
            benign_cnt += 1
        i += 1
    
    sample_cnt = min(benign_cnt, ddos_cnt)

    random.shuffle(ddos_samples)
    ddos_samples = ddos_samples[:sample_cnt]
    random.shuffle(benign_samples)
    benign_samples = benign_samples[:sample_cnt]
    ret_feature_list = ddos_samples + benign_samples
    ret_label_list = ([0] * sample_cnt) + ([1] * sample_cnt)
    return ret_feature_list, ret_label_list

def extract_pcaps(dataset_folder, output_folder):
    print(dataset_folder, output_folder)
    feature_list = list()
    label_list = list()
    extract_log_fd = open(os.path.join(output_folder, "extract_pcaps.log"), "w")
    # ddos samples, bengin samples
    label_count = [0, 0]
    total_flow = 0
    # ddos flows, bengin flows
    flow_count = [0, 0]
    
    for f in os.listdir(dataset_folder):
        if os.path.splitext(f)[-1] != ".pcap":
            continue
        print("Processing {}".format(f))
        log_list = list()
        flow_list = process_pcap(os.path.join(dataset_folder, f), log_list)
        total_flow += len(flow_list)
        # dump log
        for row in log_list:
            extract_log_fd.write(row + "\n")
        
        calculate_flow_features(flow_list, feature_list, label_list, label_count, flow_count)

    print("total flow: {}, ddos flows: {}, bengin flows: {}".format(total_flow, flow_count[0], flow_count[1]))
    print("total samples: {}, ddos samples: {}, bengin samples: {}".format(len(feature_list), label_count[0], label_count[1]))
    
    feature_list, label_list = balance_dataset(feature_list, label_list)

    feature_list = np.array(feature_list)
    label_list = np.array(label_list)
    X_train, X_test, Y_train, Y_test = train_test_split(feature_list, label_list, train_size=0.9, shuffle=True)
    X_train, X_val, Y_train, Y_val = train_test_split(X_train, Y_train, train_size=0.9, shuffle=True)

    log_string = "X_train shape: {}, Y_train shape: {}\n X_val shape: {}, Y_val shape: {}\n X_test shape: {} Y_test shape: {}".format(
        X_train.shape, Y_train.shape, X_val.shape, Y_val.shape, X_test.shape, Y_test.shape)
    print(log_string)

    hf = h5py.File(os.path.join(output_folder, "dataset_train.hdf5"), "w")
    hf.create_dataset("set_x", data=X_train)
    hf.create_dataset("set_y", data=Y_train)
    hf.close()

    hf = h5py.File(os.path.join(output_folder, "dataset_val.hdf5"), "w")
    hf.create_dataset("set_x", data=X_val)
    hf.create_dataset("set_y", data=Y_val)
    hf.close()

    hf = h5py.File(os.path.join(output_folder, "dataset_test.hdf5"), "w")
    hf.create_dataset("set_x", data=X_test)
    hf.create_dataset("set_y", data=Y_test)
    hf.close()

    extract_log_fd.close()
    return

def main():
    parser = argparse.ArgumentParser(
        description='Dataset parser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dataset_folder', nargs='+', type=str,
                        help='Folder with the dataset')
    parser.add_argument('-o', '--output_folder', nargs='+', type=str,
                        help='Output folder')

    args = parser.parse_args()

    if args.dataset_folder:
        dataset_folder = args.dataset_folder[0]
        if args.output_folder:
            output_folder = args.output_folder[0]
        else:
            output_folder = dataset_folder
        extract_pcaps(dataset_folder, output_folder)
    
    

if __name__ == '__main__':
    main()