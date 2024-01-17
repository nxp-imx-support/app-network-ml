# -*- coding: utf-8 -*-
"""
@File    :   tfl_predict.py
@Time    :   2023/09/22 11:18:18
@Author  :   Ziheng Xu
@Desc    :   Inference using the quantized TFL model
"""

import argparse
import tflite_runtime.interpreter as tflite
from utils import load_data, ID_TO_TRAFFIC, ID_TO_APP, ID_TO_CIC, ID_TO_NXP
import numpy as np
from sklearn.metrics import classification_report
import time
import datetime
from preprocess import parse_pcap, extract_feature
from config import MAX_SAMPLE_CNT, FLOW_LEN, WIN_SIZE, MAX_LENGTH, MINI_PCAP
from collections import Counter
from traffic_flow import TrafficFlowKey
from traffic_class_report import TrafficFlowResult, InferenceReport, print_inference_report, export_inferene_report
import signal
import os
import pickle


def sig_handler(s, f):
    os.killpg(os.getpgid(0), 9)


signal.signal(signal.SIGINT, sig_handler)

# Different process according to the type of dataset param.
def predict(model_path, X, ext_delegate, inference_report=None):
    dataset_size = X.shape[0]
    if dataset_size == 0:
        return list()
    ext_delegate_options = {}
    
    if ext_delegate is not None:
        print('Loading external delegate from {} with args: {}'.format(
            ext_delegate, ext_delegate_options))
        ext_delegate = [
            tflite.load_delegate(ext_delegate, ext_delegate_options)
        ]

    model = tflite.Interpreter(model_path=model_path, experimental_delegates=ext_delegate)
    model.allocate_tensors()
    input_desc = model.get_input_details()[0]
    output_desc = model.get_output_details()[0]
    print("input_desc_type {}".format(input_desc['dtype']))
    input_scale, input_zero_point = input_desc['quantization']
    print("input_scale: {}; input_zero_point: {}".format(input_scale, input_zero_point))

    print("X shape: {}".format(X.shape))
    #warmup
    w_t = 0
    # for i, x in enumerate(X):
    #     if i > 100:
    #         break
    x = X[0]
    input_data = x / input_scale + input_zero_point
    input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
    model.set_tensor(input_desc['index'], input_data)
    w_t1 = time.time()
    model.invoke()
    w_t2 = time.time()
    tmp = np.squeeze(model.get_tensor(output_desc['index']))
    w_t += (w_t2 - w_t1)
    
    print("warm up time: {} ms per 100 samples".format(w_t * 1000 * 100))
    if inference_report:
        inference_report.warmup_time = w_t * 1000 * 100
    
    # start predicting
    print("dataset size: {}".format(dataset_size))
    Y_pred = list()
    t = 0
    for i, x in enumerate(X):
        if i % 100 == 0:
            print("step {}/{}".format(i, dataset_size))

        input_data = x / input_scale + input_zero_point
        input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
        model.set_tensor(input_desc['index'], input_data)
        t1 = time.time()
        model.invoke()
        t2 = time.time()
        tmp = np.squeeze(model.get_tensor(output_desc['index']))
        t += (t2 - t1)
        tmp = input_scale * (tmp - input_zero_point)
        Y_pred.append(np.argmax(tmp))
    
    print("[DEBUG] prediction time: {} ms per 100 samples".format(t * 1000 / dataset_size * 100))
    if inference_report:
        inference_report.inference_time = t * 1000 / dataset_size * 100

    return Y_pred


def evaluate_cls(Y_pred, Y, id_to_label):
    log_predict_result(Y_pred, id_to_label)
    if Y[0] == -1:
        print("unknown label, cannot evaluate.")
        return
    Y_pred = np.array(Y_pred)
    # dataset_size = Y_pred.shape[0]
    # Y_pred = Y_pred.reshape(dataset_size, 1)
    print("Y_pred shape: {}, Y shape: {}".format(Y_pred.shape, Y.shape))
    print(classification_report(Y, Y_pred, digits=4))
    return


def log_predict_result(Y_pred, id_to_label):
    fd = open("./output_dir/predict_result.log", "a")
    ts = datetime.datetime.now()
    fd.write("====={}=====\n".format(ts.strftime("%Y-%m-%d %H:%M:%S")))
    for y in Y_pred:
        fd.write(id_to_label.get(y, "unknown") + "\n")
    cnt_list = Counter(Y_pred)
    size = len(Y_pred)
    print("Totally analysis {} packets.".format(size))
    for id, cnt in cnt_list.items():
        print("{}: {:.2f}".format(id_to_label.get(id, "unknown"), cnt / size))
    fd.close()


def pcap_inference(pcap_path, model_path, ext_delegate, class_num):
    inference_report = InferenceReport()
    inference_report.class_num = class_num
    flow_list = dict()
    parse_pcap(pcap_path, MAX_SAMPLE_CNT, None, flow_list)
    dataset = np.empty((0, MAX_LENGTH, WIN_SIZE))
    dataset_companion = list()
    inference_report.flow_cnt = len(flow_list)
    print("[DEBUG] before extract feature.")
    t1 = time.time()
    for k, flow in flow_list.items():
        if flow.pkt_cnt < FLOW_LEN:
            continue
        flow_features = extract_feature(flow, WIN_SIZE, "test")
        dataset = np.concatenate((dataset, flow_features), axis=0)
        dataset_companion += ([flow.tfkey] * len(flow_features))
    print("[DEBUG] finished extract feature, time cost: {:.2f}s".format(time.time() - t1))
    # dataset = dataset.reshape(-1, MAX_LENGTH, WIN_SIZE)
    Y_pred = predict(model_path, dataset, ext_delegate, inference_report)
    
    ret_cnt = len(Y_pred)
    cur_flow = dataset_companion[0]
    cur_flow_pkts = list()
    flow_cls_ret = list()
    for i in range(ret_cnt):
        if dataset_companion[i] != cur_flow:
            counter = np.bincount(cur_flow_pkts)
            tmp = TrafficFlowResult(cur_flow, counter.argmax(), len(cur_flow_pkts), cur_flow_pkts)
            flow_cls_ret.append(tmp)
            cur_flow_pkts = list()
            cur_flow = dataset_companion[i]
        cur_flow_pkts.append(Y_pred[i])

    counter = np.bincount(cur_flow_pkts)
    tmp = TrafficFlowResult(cur_flow, counter.argmax(), len(cur_flow_pkts), cur_flow_pkts)
    flow_cls_ret.append(tmp)

    inference_report.set_traff_flow_result(flow_cls_ret)
    log_file = "./output_dir/{}.pickle".format(time.strftime("%Y-%m-%d_%H-%M-%S"))
    with open(log_file, "wb") as fd:
        pickle.dump(inference_report, fd)

    return log_file


def main():
    parser = argparse.ArgumentParser(description="Inference using the quantized TFL model")
    parser.add_argument("--model_path", required=True, help="model path to be used.")
    parser.add_argument("--dataset", required=False, help="input dataset")
    parser.add_argument("--pcap", required=False, help="input pcap file path")
    parser.add_argument('-e', '--ext_delegate', help='external_delegate_library path')
    parser.add_argument("--traff_type", required=True, help="traff|app|cic2023")

    args = parser.parse_args()
    
    model_path = args.model_path
    dataset = args.dataset
    pcap_path = args.pcap
    traff_type = args.traff_type
    id_to_label = None

    if traff_type == "app":
        id_to_label = ID_TO_APP
    elif traff_type == "traff":
        id_to_label = ID_TO_TRAFFIC
    elif traff_type == "cic2023":
        id_to_label = ID_TO_CIC
    elif traff_type == "nxp":
        id_to_label = ID_TO_NXP
    else:
        print("traff_type error.")
        exit(0)
    if dataset is None and pcap_path is None:
        print("At least one of pcap and dataset is not empty!")
        exit(0)
    ext_delegate = args.ext_delegate

    if dataset:
        labelset = dataset.replace("_dataset_", "_label_")
        X, Y = load_data(dataset, labelset)
        Y_pred = predict(model_path, X, ext_delegate)
        evaluate_cls(Y_pred, Y, id_to_label)

    if pcap_path:
        class_num = len(id_to_label)
        # if pcap is too samll, it may not contain effective traffic. So, drop it.
        print("[INFO] processing pcap: {}".format(pcap_path))
        if os.path.getsize(pcap_path) < MINI_PCAP:
            print("[INFO] Drop {}".format(pcap_path))
            return
        log_file = pcap_inference(pcap_path, model_path, ext_delegate, class_num)
        print_inference_report(log_file, id_to_label)
        # export_inferene_report(log_file, id_to_label)
    

if __name__ == '__main__':
    main()
    # print_inference_report("./inference_report.pickle", ID_TO_NXP)


