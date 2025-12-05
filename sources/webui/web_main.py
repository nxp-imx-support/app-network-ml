# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 
# Web GUI server

from flask import Flask, render_template, jsonify
import json
import signal
import subprocess
import socket

SER_HOST = "0.0.0.0"
SER_PORT = 5000
L2FWDCAP_REPORT = "../l2capfwd_report.json"
INFERENCE_REPORT = "../model/model_infer_report.json"

app = Flask(__name__)

def get_host_ip(iface):
    result = subprocess.run(
        ["ip", "-4", "addr", "show", iface],
        capture_output=True,
        text=True,
        check=True
    )
    for line in result.stdout.split('\n'):
        if "inet " in line:
            return line.strip().split()[1].split('/')[0]
    return ""

def signal_handler(signum, frame):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        print("Signal {} recv, exit...".format(signum))
        exit(0)


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
        if atk_cnt >= 100:
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
    hostname = socket.gethostname()
    if hostname == "imx943-orangebox":
        ip_addr = get_host_ip("swp2")
        if ip_addr != "":
            SER_HOST = ip_addr
        else:
            print("[WARN] Cannot obtain the swp2 IP address, will use default 0.0.0.0")
    app.run(debug=False, port=SER_PORT, host=SER_HOST)
