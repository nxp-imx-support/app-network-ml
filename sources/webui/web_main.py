# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 
# Web GUI server

from flask import Flask, render_template, jsonify
import json
import signal

SER_HOST = "0.0.0.0"
SER_PORT = 5000
L2FWDCAP_REPORT = "../l2capfwd_report.json"
INFERENCE_REPORT = "../model/model_infer_report.json"
WHITELIST = ["192.168.0.157", "255.255.255.255", "0.0.0.0"]

app = Flask(__name__)

def signal_handler(signum, frame):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        print("Signal {} recv, exit...".format(signum))
        exit(0)

def check_whitelist(ip_part):
    for ip_addr in WHITELIST:
        if ip_addr in ip_part:
            return True
    return False

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/get_status")
def get_status_json():
    ret_dict = dict()
    with open(L2FWDCAP_REPORT) as fd:
        ret_dict = json.loads(fd.read())
    ret_dict["ip_connections_list"] = list()
    ddos_cnt = 0
    bengin_cnt = 0
    for item in ret_dict["ip_info_list"]:
        ip_part, atk_cnt = item.split(":")
        ip_part.strip()
        atk_cnt = int(atk_cnt.strip())
        if atk_cnt >= 100 and not check_whitelist(ip_part):
            ret_dict["ip_connections_list"].append([ip_part, 1])
            ddos_cnt += 1
        else:
            ret_dict["ip_connections_list"].append([ip_part, 0])
            bengin_cnt += 1
    ret_dict.pop("ip_info_list")
    # ret_dict["benign_cnt"] = ret_dict["total_cnt"] - ret_dict["ddos_cnt"]
    ret_dict["benign_cnt"] = bengin_cnt
    ret_dict["ddos_cnt"] = ddos_cnt
    ret_dict["total_cnt"] = bengin_cnt + ddos_cnt

    with open(INFERENCE_REPORT) as fd:
        ret_dict.update(json.loads(fd.read()))
    return jsonify(ret_dict)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    app.run(debug=False, port=SER_PORT, host=SER_HOST)
