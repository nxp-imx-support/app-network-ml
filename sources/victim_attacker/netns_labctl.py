# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 

import curses
import subprocess
import time
import signal

victim_server_process = None
attack_process = None
# Please check your network interfaces before running this script
# You can use 'ip link show' to list all available interfaces
# If you use another OB2.0 board, the iface_1 should be swp0.
iface_1 = "eth0"
iface_2 = "eth1"
victim_ip = "10.0.1.10/24"
default_ip = "10.0.1.9/24"
attack_opt = "--target {} --src-start 10.0.1.100 --src-end 10.0.1.200".format(victim_ip.split('/')[0])

def init_network_ns():
    """
    IFACE_1=eth0
    IFACE_2=eth1
    VICTIM_IP=10.0.1.10/24
    DEFAULT_IP=10.0.1.9/24

    # Configure default net ns
    echo "Configure default net namespace"
    ip link set ${IFACE_1} up
    ip addr add ${DEFAULT_IP} dev ${IFACE_1}

    echo "Configure victim net namespace"
    ip netns add victim_net
    ip link set ${IFACE_2} netns victim_net
    ip netns exec victim_net ip link set ${IFACE_2} up
    ip netns exec victim_net ip addr add ${VICTIM_IP} dev ${IFACE_2}

    echo "Start up victim server"
    ip netns exec victim_net python3 simple_webserver.py
    """
    subprocess.run("ip link set {} up".format(iface_1), shell=True)
    subprocess.run("ip addr flush dev {}".format(iface_1), shell=True)
    subprocess.run("ip addr add {} dev {}".format(default_ip, iface_1), shell=True)
    subprocess.run("ip netns add victim_net", shell=True)
    subprocess.run("ip link set {} netns victim_net".format(iface_2), shell=True)
    subprocess.run("ip netns exec victim_net ip link set {} up".format(iface_2), shell=True)
    subprocess.run("ip netns exec victim_net ip addr add {} dev {}".format(victim_ip, iface_2), shell=True)
    time.sleep(2)

def remove_netns():
    subprocess.run("ip netns del victim_net", shell=True)

def start_victim_server():
    global victim_server_process
    victim_server_process = subprocess.Popen("ip netns exec victim_net python3 simple_webserver.py", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(2)
    return victim_server_process.poll() is None

def start_dos_attack():
    global attack_process
    attack_process = subprocess.Popen("python3 syn_flood_attack.py {}".format(attack_opt), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(2)
    return attack_process.poll() is None

def test_victim_conn():
    host_ip = victim_ip.split('/')[0]
    ret = subprocess.run("curl --max-time 3 http://{}:8080".format(host_ip), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return ret.returncode == 0

def main(stdscr):
    curses.curs_set(0)
    current = 0
    options = ["1 - Init network namespace lab",
               "2 - Start victim server", 
               "3 - Start DoS attack",
               "4 - Stop DoS attack",
               "5 - Test victim connection",
               "6 - Exit"]
    
    netns_initialized = False
    victim_server_running = False
    attack_process_running = False
    status_message = "Ready"

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Select operations")

        for i, text in enumerate(options):
            mode = curses.A_REVERSE if i == current else curses.A_NORMAL
            stdscr.addstr(i + 2, 2, text, mode)

        height, width = stdscr.getmaxyx()
        status_bar = "NetNS: {} | Victim Server: {} | Attacker process: {} | {}".format(
            "Initialized" if netns_initialized else "Not Initialized",
            "Running" if victim_server_running else "Stopped",
            "Running" if attack_process_running else "Stopped",
            status_message
        )
        stdscr.addstr(height - 1, 0, status_bar[:width - 1], curses.A_REVERSE)

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current = (current - 1) % len(options)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(options)
        elif key in (10, 13):
            if current == 0:
                init_network_ns()
                netns_initialized = True
                status_message = "Network namespace initialized"
            elif current == 1:
                if start_victim_server():
                    victim_server_running = True
                    status_message = "Victim server started"
                else:
                    status_message = "Failed to start victim server"
            elif current == 2:
                if start_dos_attack():
                    attack_process_running = True
                    status_message = "DoS attack started"
                else:
                    status_message = "Failed to start DoS attack"
            elif current == 3:
                if attack_process:
                    attack_process.send_signal(signal.SIGINT)
                    attack_process.wait()
                attack_process_running = False
                status_message = "DoS attack stopped"
            elif current == 4:
                if test_victim_conn():
                    status_message = "Connection test successfully."
                else:
                    status_message = "Connection test failed."
            elif current == 5:
                break

        stdscr.refresh()
    
    if victim_server_process:
        victim_server_process.send_signal(signal.SIGINT)
        victim_server_process.wait()
    if attack_process:
        attack_process.send_signal(signal.SIGINT)
        attack_process.wait()
    remove_netns()


if __name__ == '__main__':
    curses.wrapper(main)
