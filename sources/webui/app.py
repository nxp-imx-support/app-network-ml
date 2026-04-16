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

app = Flask(__name__, static_folder='static')

# Configuration
REPORT_PATH = os.environ.get('REPORT_PATH', '../packets_controller/report.json')
SER_HOST = "0.0.0.0"
SER_PORT = 5000

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
    """Handle shutdown signals"""
    print(f"Signal {signum} received, shutting down...")
    sys.exit(0)

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

if __name__ == '__main__':
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Try to get interface IP for serving
    hostname = socket.gethostname()
    if hostname == "imx943-orangebox":
        ip_addr = get_host_ip("swp2")
        if ip_addr:
            SER_HOST = ip_addr
            print(f"Using interface IP: {SER_HOST}")
    
    print(f"Starting server on {SER_HOST}:{SER_PORT}")
    app.run(debug=False, host=SER_HOST, port=SER_PORT)