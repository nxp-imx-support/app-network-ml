# -*- coding: utf-8 -*-
"""
@File    :   traffic_class_report.py
@Time    :   2023/12/15 10:47:19
@Author  :   Ziheng Xu
@Desc    :   Parse inference result and print report
"""
from traffic_flow import TrafficFlowKey
import pickle
import time
import pygal

SHOW_NUM = 5

# 描述预测结果中的流信息，包含流中报文数量，分类结果，每个包的预测结果
class TrafficFlowResult(object):
    def __init__(self, tfkey: TrafficFlowKey, cls_ret: int, pkt_cnt: int, pkt_ret: list):
        super().__init__()
        self.tfkey = tfkey
        self.cls_ret = cls_ret
        self.pkt_cnt = pkt_cnt
        self.pkt_ret = pkt_ret

# 以类别为单位，描述类别中的流信息
class ClassReportEntry(object):
    def __init__(self):
        super().__init__()
        # 属于当前类别的流数量
        self.cnt = 0
        # 流列表，元素类型为TrafficFlowResult
        self.flow_list = list()
        # 属于当前类别的包数量
        self.pkt_cnt = 0

    def add_flow_list(self, flow: TrafficFlowResult):
        self.cnt += 1
        self.pkt_cnt += flow.pkt_cnt
        self.flow_list.append(flow)


class InferenceReport(object):
    def __init__(self):
        super().__init__()
        self.traff_flow_result = list()
        self.flow_cnt = 0
        self.effective_flow_cnt = 0
        self.effective_packets_cnt = 0
        # key表示类别标签，value类型为ClassReportEntry
        self.class_detail = dict()

        self.inference_time = 0
        self.warmup_time = 0

        self.class_num = 0

    def set_traff_flow_result(self, f_list: TrafficFlowResult):
        self.traff_flow_result = f_list
        self.effective_flow_cnt = len(f_list)
        for item in f_list:
            self.effective_packets_cnt += item.pkt_cnt
            c_key = item.cls_ret
            if c_key not in self.class_detail.keys():
                self.class_detail[c_key] = ClassReportEntry()
            self.class_detail[c_key].add_flow_list(item)
            

def print_inference_report(infer_report_f, id_to_label):
    fd = open(infer_report_f, "rb")
    infer_report = pickle.load(fd)
    fd.close()
    print("warmup time: {}ms, inference time: {}ms".format(infer_report.warmup_time, infer_report.inference_time))
    
    print("=====pcap info=====")
    print("packets:           {}".format(infer_report.effective_packets_cnt))
    print("effective flows:   {}".format(infer_report.effective_flow_cnt))
    print("flows:             {}".format(infer_report.flow_cnt))
    print("==========")
    
    print("=====class detail=====")
    for label_id, class_entry in infer_report.class_detail.items():
        print("*****{}*****".format(id_to_label.get(label_id)))
        print("{}:    {:.2f}%".format(id_to_label.get(label_id), class_entry.pkt_cnt / infer_report.effective_packets_cnt * 100))
        show_num = len(class_entry.flow_list)
        if show_num > 10:
            show_num = 10
        for i in range(show_num):
            tmp = class_entry.flow_list[i]
            print("{}:{}, {}:{}, {}".format(tmp.tfkey.src_ip, tmp.tfkey.src_port, tmp.tfkey.dst_ip, tmp.tfkey.dst_port, tmp.tfkey.proto))


def draw_performance_fig(warmup_time, inference_time):
    bar_chart = pygal.HorizontalBar(height=100)
    # bar_chart.title = "Performance"
    bar_chart.add("warmup time", warmup_time)
    bar_chart.add("inference time", inference_time)
    bar_chart.render_to_png("./output_dir/fig1.png")

def draw_classes_rate_fig(classes_rate_dict):
    pie_chart = pygal.Pie(inner_radius=.4, height=300, width=400)
    for class_name, rate in classes_rate_dict.items():
        pie_chart.add(class_name, rate)
    pie_chart.render_to_png("./output_dir/fig2.png")


def export_inferene_report(infer_report_f, id_to_label):
    fd = open(infer_report_f, "rb")
    infer_report = pickle.load(fd)
    fd.close()

    out_fd = open("./output_dir/report.md", "w")
    lines = list()

    lines.append("# DeepPacket Inference Report\n")
    lines.append("Created by {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))
    lines.append("## Captured file information\n")
    lines.append("- packets:           {}\n".format(infer_report.effective_packets_cnt))
    lines.append("- effective flows:   {}\n".format(infer_report.effective_flow_cnt))
    lines.append("- captured flows:    {}\n".format(infer_report.flow_cnt))

    lines.append("## Performance\n")
    lines.append("Warm up time:   {:.3f}ms per 100 packets\n\n".format(infer_report.warmup_time))
    lines.append("Inference time: {:.3f}ms per 100 packets\n\n".format(infer_report.inference_time))

    draw_performance_fig(infer_report.warmup_time, infer_report.inference_time)
    lines.append("![](fig1.png)\n")

    lines.append("## Classes details\n")
    lines.append("![](fig2.png)\n\n")
    classes_rate_dict = {}
    for label_id in range(infer_report.class_num):
        if label_id in infer_report.class_detail.keys():
            class_entry = infer_report.class_detail[label_id]
            classes_rate_dict[id_to_label.get(label_id)] = class_entry.cnt
            lines.append("#### {}\n".format(id_to_label.get(label_id)))
            lines.append("traffic rate: **{:.2f}%**\n".format(class_entry.cnt / infer_report.effective_flow_cnt * 100))
            show_num = len(class_entry.flow_list)

            too_many_flag = False
            if show_num > SHOW_NUM:
                show_num = SHOW_NUM
                too_many_flag = True
            if show_num == 0:
                continue
            lines.append("\n| src_ip:port | dst_ip:port | protocol type |\n")
            lines.append("| ---- | ---- | ---- |\n")
            for i in range(show_num):
                tmp = class_entry.flow_list[i]
                lines.append("| {}:{} | {}:{} | {} |\n".format(tmp.tfkey.src_ip, tmp.tfkey.src_port, tmp.tfkey.dst_ip, tmp.tfkey.dst_port, tmp.tfkey.proto))
            
            if too_many_flag:
                lines.append("| ... | ... | ... |\n")
        else:
            lines.append("#### {}\n".format(id_to_label.get(label_id)))
            lines.append("traffic rate: **0**\n")

    draw_classes_rate_fig(classes_rate_dict)
    out_fd.writelines(lines)
    out_fd.close()
        

    