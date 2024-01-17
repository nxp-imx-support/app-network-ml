# -*- coding: utf-8 -*-
"""
@File    :   preprocess.py
@Time    :   2023/09/07 11:04:54
@Author  :   Ziheng Xu
@Desc    :   Preprocess pcap files
"""

"""
Remove Ethernet header
Pad traffic with UDP header with zeros to the length of 20 bytes
Mask the IP in the IP header
Remove irrelevant packets such as packets with no payload or DNS packets
Convert the raw packet into a bytes vector
Truncate the vector of size more than 1500, pad zeros for the byte vector less than 1500
Normalise the bytes vector by dividing each element by 255
"""

import dpkt
import os
import csv
from traffic_flow import TrafficFlowKey, TrafficFlow
from utils import PREFIX_TO_APP_ID, PREFIX_TO_TRAFFIC_ID, PREFIX_TO_CIC_ID
from utils import PREFIX_TO_NXP_ID
import numpy as np
import argparse
import ipaddress
from config import WIN_SIZE, MAX_LENGTH, FLOW_LEN

# pcap_dir = "/opt/Dataset/ISCX2016"
# feature_dir = "./feature_dir"

def print_hex(bytes):
    l = [hex(int(i)) for i in bytes]
    print(" ".join(l))


def mask_ip(ip_pkt, tfkey: TrafficFlowKey = None):
    # store real ip before mask
    if tfkey is not None:
        src_ip = ipaddress.ip_address(ip_pkt.src)
        tfkey.src_ip = str(src_ip)
        dst_ip = ipaddress.ip_address(ip_pkt.dst)
        tfkey.dst_ip = str(dst_ip)
    
    # IPv4
    if isinstance(ip_pkt, dpkt.ip.IP):
        ip_pkt.src = b'\x00\x00\x00\x00'
        ip_pkt.dst = b'\x00\x00\x00\x00'
    elif isinstance(ip_pkt, dpkt.ip6.IP6):
        ip_pkt.src = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        ip_pkt.dst = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    else:
        return None
    return ip_pkt


def process_udp(ip_pkt, tfkey: TrafficFlowKey = None):
    if (isinstance(ip_pkt, dpkt.ip.IP) and ip_pkt.p == dpkt.ip.IP_PROTO_UDP) or (isinstance(ip_pkt, dpkt.ip6.IP6) and ip_pkt.nxt == dpkt.ip.IP_PROTO_UDP):
        udp = ip_pkt.data
        
        if tfkey is not None:
            tfkey.src_port = udp.sport
            tfkey.dst_port = udp.dport
            tfkey.proto = "udp"

        if udp.sport == 53 or udp.dport == 53:
            return None
        if udp.sport == 5353 or udp.dport == 5353:
            return None
        if len(udp.data) == 0:
            return None
        
        pad = b'\x00' * 12
        udp.data = pad + udp.data
        ip_pkt.data = udp

    return ip_pkt


def process_tcp(ip_pkt, tfkey: TrafficFlowKey = None):
    if (isinstance(ip_pkt, dpkt.ip.IP) and ip_pkt.p == dpkt.ip.IP_PROTO_TCP) or (isinstance(ip_pkt, dpkt.ip6.IP6) and ip_pkt.nxt == dpkt.ip.IP_PROTO_TCP):
        tcp = ip_pkt.data

        if tfkey is not None:
            tfkey.src_port = tcp.sport
            tfkey.dst_port = tcp.dport
            tfkey.proto = "tcp"

        if len(tcp.data) == 0 or (tcp.flags & 0x03):
            return None
    return ip_pkt


def packet_to_sparse_array(pkt, max_length=MAX_LENGTH):
    arr = np.frombuffer(pkt.pack(), dtype=np.uint8)[0:max_length] / 255
    if len(arr) < max_length:
        pad_width = max_length - len(arr)
        arr = np.pad(arr, pad_width=(0, pad_width), constant_values=0)
    return arr

def parse_pcap(pcap_path, max_sample=1000, prefix_to_id=None, flow_list=None):
    fd = open(pcap_path, "rb")
    magic_head = fd.read(4)
    fd.seek(0, 0)

    pcap_reader = None
    if magic_head == b'\n\r\r\n':
        pcap_reader = dpkt.pcapng.Reader(fd)
    elif magic_head == b'\xd4\xc3\xb2\xa1':
        pcap_reader = dpkt.pcap.Reader(fd)
    else:
        print("[DEBUG in PcapUtils] It is not a pcap or pcapng file.")
        print("Magic Header: {}".format(magic_head.hex()))
        return None

    if pcap_reader is None:
        return None

    prefix = os.path.basename(pcap_path).split(".")[0].lower()
    # -1 represents unknown label
    if prefix_to_id is None:
        label = -1
    else:
        label = prefix_to_id.get(prefix, -1)
    
    pkt_cnt = 0

    for ts, buf in pcap_reader:
        eth = dpkt.ethernet.Ethernet(buf)
        ip_layer = None
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip_layer = eth.data
        else:
            continue

        tfkey = TrafficFlowKey("", "", 0, 0, "")
        ip_pkt = mask_ip(ip_layer, tfkey)
        if ip_pkt is None:
            continue

        ip_pkt = process_udp(ip_pkt, tfkey)
        if ip_pkt is None:
            continue

        ip_pkt = process_tcp(ip_pkt, tfkey)
        if ip_pkt is None:
            continue

        vec = packet_to_sparse_array(ip_pkt)

        tfkey.order_ports()
        if tfkey.src_port == 0 or tfkey.dst_port == 137:
            continue

        if flow_list is not None:
            if tfkey not in flow_list.keys():
                flow_list[tfkey] = TrafficFlow(tfkey)
            flow_list[tfkey].add_pkt(vec)

        pkt_cnt += 1
        # limit packets num
        if max_sample > 0 and pkt_cnt >= max_sample:
            break

    fd.close()
    return label


def split_train_test(vec_list, test_rate=0.2, sample_top=5000):
    np.random.shuffle(vec_list)
    vec_list = vec_list[:sample_top]

    size = len(vec_list)
    train_size = int(size * (1 - test_rate))
    train_set = vec_list[:train_size]
    test_set = vec_list[train_size:]
    return train_set, test_set
    
# Slide window to extract feature from single flow
def extract_feature(flow: TrafficFlow, win_size: int, mode="train"):
    step_length = 1 if mode == "train" else win_size
    left_idx = 0
    right_idx = win_size
    vec_len = len(flow.pkt_list[0])
    ret = np.empty((0, win_size, vec_len))
    # print("[DEBUG] flow.pkt_cnt: {}".format(flow.pkt_cnt))
    if right_idx > flow.pkt_cnt:
        tmp = np.array(flow.pkt_list[left_idx: flow.pkt_cnt])
        pad = np.zeros((right_idx - flow.pkt_cnt, vec_len))
        tmp = np.concatenate((tmp, pad), axis=0)
        tmp = np.expand_dims(tmp, axis=0)
        ret = np.concatenate((ret, tmp), axis=0)
    
    while right_idx <= flow.pkt_cnt:
        # print("[DEBUG] left_idx: {}, right_idx: {}".format(left_idx, right_idx))
        tmp = np.array(flow.pkt_list[left_idx:right_idx])
        tmp = np.expand_dims(tmp, axis=0)
        # print("[DEBUG] tmp shape: {}".format(tmp.shape))
        ret = np.concatenate((ret, tmp), axis=0)
        # print("[DEBUG] ret shape: {}".format(ret.shape))
        left_idx += step_length
        right_idx += step_length
    
    # transpose for channel last
    # print("[DEBUG] ret: {}".format(ret))
    ret = ret.transpose(0, 2, 1)
    # print("[DEBUG] ret shape: {}".format(ret.shape))
    return ret


def main():
    argparser = argparse.ArgumentParser(description="Preprocess pcap files.")
    argparser.add_argument("--feature_dir", "-f", required=True, help="store features after preprocessing")
    argparser.add_argument("--pcap_dir", "-p", required=True, help="pcaps path")
    argparser.add_argument("--traff_type", "-t", required=True, help="app|traff|cic2023")
    args = argparser.parse_args()

    pcap_dir = args.pcap_dir
    feature_dir = args.feature_dir
    traff_type = args.traff_type
    
    PREFIX_TO_ID = None

    if traff_type == "app":
        PREFIX_TO_ID = PREFIX_TO_APP_ID
    if traff_type == "traff":
        PREFIX_TO_ID = PREFIX_TO_TRAFFIC_ID
    if traff_type == "cic2023":
        PREFIX_TO_ID = PREFIX_TO_CIC_ID
    if traff_type == "nxp":
        PREFIX_TO_ID = PREFIX_TO_NXP_ID
    else: 
        print("traff_type error.")
        exit(0)

    total_cnt = len(os.listdir(pcap_dir))
    i = 1

    dataset = dict()

    for pcap in os.listdir(pcap_dir):
        if os.path.splitext(pcap)[-1] != ".pcap":
            continue
        print("[INFO] processing {}, {}/{}".format(pcap, i, total_cnt))
        flow_list = dict()
        label = parse_pcap(os.path.join(pcap_dir, pcap), 1500, PREFIX_TO_ID, flow_list)
        if label is None:
            continue
        if label not in dataset.keys():
            dataset[label] = np.empty((0, MAX_LENGTH, WIN_SIZE))
        for k, flow in flow_list.items():
            if flow.pkt_cnt < FLOW_LEN:
                continue
            tmp = extract_feature(flow, WIN_SIZE)
            dataset[label] = np.concatenate((dataset[label], tmp), axis=0)
        i += 1
    
    # Process traffic dataset
    traff_train = np.empty((0, MAX_LENGTH, WIN_SIZE))
    traff_train_label = np.empty((0))
    traff_test = np.empty((0, MAX_LENGTH, WIN_SIZE))
    traff_test_label = np.empty((0))
    for label in dataset.keys():
        print("[INFO] processing traffic label {}, data size: {}".format(label, len(dataset[label])))
        train_set, test_set = split_train_test(dataset[label], sample_top=8000)
        
        traff_train = np.concatenate((traff_train, train_set), axis=0)
        label_set = np.array([label] * train_set.shape[0])
        traff_train_label = np.concatenate((traff_train_label, label_set), axis=0)

        traff_test = np.concatenate((traff_test, test_set), axis=0)
        label_set = np.array([label] * test_set.shape[0])
        traff_test_label = np.concatenate((traff_test_label, label_set), axis=0)

        print("[INFO] train set shape: {}, test set shape: {}".format(train_set.shape, test_set.shape))

    # np.savetxt(os.path.join(feature_dir, "{}_dataset_train.csv".format(traff_type)), traff_train, delimiter=',')
    # np.savetxt(os.path.join(feature_dir, "{}_dataset_test.csv".format(traff_type)), traff_test, delimiter=',')
    np.save(os.path.join(feature_dir, "{}_dataset_train.npy".format(traff_type)), traff_train)
    np.save(os.path.join(feature_dir, "{}_label_train.npy".format(traff_type)), traff_train_label)
    np.save(os.path.join(feature_dir, "{}_dataset_test.npy".format(traff_type)), traff_test)
    np.save(os.path.join(feature_dir, "{}_label_test.npy".format(traff_type)), traff_test_label)

if __name__ == '__main__':
    main()