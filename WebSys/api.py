# -*- coding: utf-8 -*-
"""
@File    :   api.py
@Time    :   2024/01/09 21:08:14
@Author  :   Ziheng Xu
@Desc    :   Back-end api code
"""


import sys
from conf import DEEPPACKET_DIR
sys.path.append(DEEPPACKET_DIR)
import pickle
import json
import os
import subprocess
from traffic_class_report import InferenceReport, ClassReportEntry
from utils import ID_TO_NXP

dpOutput = os.path.join(DEEPPACKET_DIR, "output_dir")
id_to_label = ID_TO_NXP

class DPInferReportItem(object):
    def __init__(self, infer_report):
        self.infer_time = infer_report.inference_time
        self.warmup_time = infer_report.warmup_time
        self.flow_cnt = infer_report.effective_flow_cnt
        self.pkt_cnt = infer_report.effective_packets_cnt
        # {class_label: class_cnt}
        self.class_counter = dict()
        # flow list
        self.flow_list = set()
        for label_id in range(infer_report.class_num):
            if label_id in infer_report.class_detail.keys():
                class_entry = infer_report.class_detail[label_id]
                self.class_counter[id_to_label.get(label_id)] = class_entry.pkt_cnt
                
                for flow in class_entry.flow_list:
                    item = (flow.tfkey.src_ip, flow.tfkey.src_port, flow.tfkey.dst_ip, flow.tfkey.dst_port, flow.tfkey.proto, id_to_label.get(label_id))
                    self.flow_list.add(item)
            else:
                self.class_counter[id_to_label.get(label_id)] = 0


class DPResJson(object):
    def __init__(self, class_labels):
        self.item_cnt = 0
        self.infer_time = 0
        self.warmup_time = 0
        self.flow_cnt = 0
        self.pkt_cnt = 0
        # {class_label: class_cnt}
        self.class_counter = dict()
        for label in class_labels:
            self.class_counter[label] = 0
        # flow list
        self.flow_list = set()

    def add_report_item(self, report_item):
        self.item_cnt += 1
        self.infer_time += report_item.infer_time
        self.warmup_time += report_item.warmup_time
        self.flow_cnt += report_item.flow_cnt
        self.pkt_cnt += report_item.pkt_cnt
        
        # TODO self.flow_list 
        self.flow_list.update(report_item.flow_list)
        # self.class_counter
        for key in self.class_counter.keys():
            self.class_counter[key] += report_item.class_counter[key]
        
    def calc_performance(self):
        if self.item_cnt == 0:
            return
        self.infer_time = round(self.infer_time / self.item_cnt, 2)
        self.warmup_time = round(self.warmup_time / self.item_cnt, 2)

    def __iter__(self):
        yield from {
            "infer_time": self.infer_time,
            "warmup_time": self.warmup_time,
            "flow_cnt": self.flow_cnt,
            "pkt_cnt": self.pkt_cnt,
            "class_counter": self.class_counter,
            "flow_list": list(self.flow_list)
        }.items()

    def __str__(self):
        return json.dumps(dict(self))

    def __repr__(self):
        return self.__str__()

def is_file_opend(fpath):
    result = subprocess.run(['fuser', fpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    return False

def parse_dp_report(report_path):
    if is_file_opend(report_path):
        return None
    fd = open(report_path, "rb")
    infer_report = pickle.load(fd)
    fd.close()
    return DPInferReportItem(infer_report)

def generate_dp_response():
    dp_res = DPResJson(list(id_to_label.values()))
    for dp_report_f in os.listdir(dpOutput):
        if os.path.splitext(dp_report_f)[-1] != ".pickle":
            continue
        item = parse_dp_report(os.path.join(dpOutput, dp_report_f))
        if item:
            dp_res.add_report_item(item)

    dp_res.calc_performance()
    return dp_res


    