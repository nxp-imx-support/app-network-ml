# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Launcher: starts WebUI only. Use the WebUI buttons to start/stop
# packets_controller and ml_detector.

import subprocess
import signal
import sys
import time

quit_flag = False


def handle_sigint(sig, frame):
    global quit_flag
    print("Capture Ctrl-C signal")
    quit_flag = True


def setup_network_bridge():
    port_0 = "swp0"
    port_1 = "eth1"
    bridge_name = "br0"

    p_ret = subprocess.run(f"ip link show {bridge_name}", shell=True)
    if p_ret.returncode == 0:
        print("Bridge already exists, removing")
        subprocess.run(f"ip link del {bridge_name}", shell=True)

    time.sleep(2)
    print("Creating bridge")
    subprocess.run(f"ip link add name {bridge_name} type bridge", shell=True)
    subprocess.run(f"ip link set dev {port_0} master {bridge_name}", shell=True)
    subprocess.run(f"ip link set dev {port_1} master {bridge_name}", shell=True)
    subprocess.run(f"ip link set {bridge_name} up", shell=True)
    subprocess.run(f"ip link set {port_0} up", shell=True)
    subprocess.run(f"ip link set {port_1} up", shell=True)
    time.sleep(2)


def remove_network_bridge():
    bridge_name = "br0"
    port_0 = "swp0"
    port_1 = "eth1"

    print("Removing bridge")
    subprocess.run(f"ip link set dev {port_0} nomaster", shell=True)
    subprocess.run(f"ip link set dev {port_1} nomaster", shell=True)
    subprocess.run(f"ip link del {bridge_name}", shell=True)
    time.sleep(2)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_sigint)

    webui_log = open("logs/webui.log", "w")

    setup_network_bridge()

    webui = subprocess.Popen(["python3", "app.py"], cwd="webui",
                             stdout=webui_log, stderr=webui_log)

    time.sleep(2)

    if webui.poll() is not None:
        print("Error: webui failed to start")
        quit_flag = True
    else:
        print("i.MX DDoS Blocker WebUI started. Press Ctrl+C to exit...")

    while not quit_flag:
        time.sleep(1)

    webui.send_signal(signal.SIGINT)
    webui.wait()

    webui_log.close()

    remove_network_bridge()

    print("All exit. Runtime logs can be found in logs/ folder")
