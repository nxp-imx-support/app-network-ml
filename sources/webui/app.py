# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Web API server for DDoS Blocker dashboard

from flask import Flask, send_from_directory, jsonify
import json
import os
import psutil
import socket
import signal
import sys
import subprocess
import time

app = Flask(__name__, static_folder='static')

# Configuration
REPORT_PATH = os.environ.get('REPORT_PATH', '../packets_controller/report.json')
SER_HOST = "0.0.0.0"
SER_PORT = 5000

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKT_CTL_DIR = os.path.join(BASE_DIR, "../packets_controller")
ML_DIR = os.path.join(BASE_DIR, "../ml_detector")
LOGS_DIR = os.path.join(BASE_DIR, "../logs")

# Managed subprocesses and their log files
_pkt_controller = None
_ml_detector = None
_pkt_log = None
_ml_log = None
_quit = False

def get_host_ip(iface):
    """Get IP address of specified interface"""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split('\n'):
            if "inet " in line:
                return line.strip().split()[1].split('/')[0]
    except:
        pass
    return ""

def signal_handler(signum, frame):
    global _quit
    _quit = True

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return send_from_directory('static', 'index.html')

@app.route('/api/stats')
def get_stats():
    """Get statistics from report.json and add system metrics"""
    try:
        # Read report.json
        with open(REPORT_PATH, 'r') as f:
            data = json.load(f)
        
        # Add system metrics if not present
        data['cpu_percent'] = psutil.cpu_percent(interval=0.1)
        
        # Memory stats
        mem = psutil.virtual_memory()
        data['ram_percent'] = mem.percent
        data['ram_used_mb'] = mem.used // (1024 * 1024)
        data['ram_total_mb'] = mem.total // (1024 * 1024)
        
        # Network stats
        net = psutil.net_io_counters()
        data['net_rx_bytes'] = net.bytes_recv
        data['net_tx_bytes'] = net.bytes_sent
        data['net_rx_packets'] = net.packets_recv
        data['net_tx_packets'] = net.packets_sent
        
        # Calculate additional metrics
        if data.get('time_period', 0) > 0:
            data['throughput_pps'] = ((data['xdp_rx_packets'] - data.get('previous_rx_packets', 0)) + 
                                     (data['xdp_pass_packets'] - data.get('previous_pass_packets', 0))) / data['time_period']
        
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({'error': 'Report file not found'}), 503
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _start_processes():
    global _pkt_controller, _ml_detector, _pkt_log, _ml_log
    os.makedirs(LOGS_DIR, exist_ok=True)
    if _pkt_controller is None or _pkt_controller.poll() is not None:
        _pkt_log = open(os.path.join(LOGS_DIR, "pkt_controller.log"), "w")
        _pkt_controller = subprocess.Popen(
            ["./packets_controller_main", "-i", "swp0", "-m", "swp0", "-p", "./xdp_forward_kern.o"],
            cwd=PKT_CTL_DIR, stdout=_pkt_log, stderr=_pkt_log)
        time.sleep(3)
    if _ml_detector is None or _ml_detector.poll() is not None:
        _ml_log = open(os.path.join(LOGS_DIR, "ml_detector.log"), "w")
        _ml_detector = subprocess.Popen(
            ["python3", "detector_main.py"],
            cwd=ML_DIR, stdout=_ml_log, stderr=_ml_log)


def _stop_processes():
    global _pkt_controller, _ml_detector, _pkt_log, _ml_log
    for proc in (_pkt_controller, _ml_detector):
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            proc.wait()
    _pkt_controller = None
    _ml_detector = None
    for f in (_pkt_log, _ml_log):
        if f:
            f.close()
    _pkt_log = None
    _ml_log = None


@app.route('/api/control/start', methods=['POST'])
def control_start():
    _start_processes()
    return jsonify({'message': 'Started'})


@app.route('/api/control/stop', methods=['POST'])
def control_stop():
    _stop_processes()
    return jsonify({'message': 'Stopped'})


@app.route('/api/control/reset', methods=['POST'])
def control_reset():
    _stop_processes()
    _start_processes()
    return jsonify({'message': 'Reset complete'})

if __name__ == '__main__':
    import threading

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    hostname = socket.gethostname()
    if hostname == "imx943-orangebox":
        ip_addr = get_host_ip("swp2")
        if ip_addr:
            SER_HOST = ip_addr
            print(f"Using interface IP: {SER_HOST}")

    print(f"Starting server on {SER_HOST}:{SER_PORT}")
    threading.Thread(
        target=lambda: app.run(debug=False, host=SER_HOST, port=SER_PORT),
        daemon=True
    ).start()

    while not _quit:
        time.sleep(1)

    _stop_processes()
    sys.exit(0)