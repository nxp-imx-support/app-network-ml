# -*- coding: utf-8 -*-
"""
@File    :   main.py
@Time    :   2024/01/09 21:05:51
@Author  :   Ziheng Xu
@Desc    :   Flask app entry
"""

from flask import Flask, render_template, jsonify
import api
import psutil
import time
from conf import SER_HOST, SER_PORT

app = Flask(__name__)  
last_pkts = 0

def get_net_io_pkts():
    net_counter = psutil.net_io_counters()
    return net_counter.packets_recv + net_counter.packets_sent

  
@app.route('/')  
def home():  
    return render_template('home.html')  

# For AJAX request
@app.route('/get_all_infer_report', methods=['post'])
def get_all_infer_report():
    all_infer_report = api.generate_dp_response()
    return jsonify(dict(all_infer_report))

@app.route('/get_pkts_now', methods=['post'])
def get_pkts_now():
    global last_pkts
    pkts_now = get_net_io_pkts()
    ret = jsonify({"time": time.strftime("%H:%M:%S"), "pkt_num": pkts_now - last_pkts})
    last_pkts = pkts_now
    return ret

# Running flask app
if __name__ == '__main__':  
    last_pkts = get_net_io_pkts()
    app.run(debug=True, port=SER_PORT, host=SER_HOST)