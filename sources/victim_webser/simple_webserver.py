# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 

from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import socket

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

class Request(BaseHTTPRequestHandler):
    def do_GET(self):
        html_fd = open("index_example.html", "rb")
        html_res = html_fd.read()
        html_fd.close()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_res)

if __name__ == '__main__':
    host = ("0.0.0.0", 8080)
    hostname = socket.gethostname()
    if hostname == "imx943-orangebox":
        ip_addr = get_host_ip("eth1")
        if ip_addr != "":
            host = (ip_addr, 8080)
        else:
            print("[WARN] Cannot obtain the eth1 IP address, will use default 0.0.0.0")
    server = HTTPServer(host, Request)
    print("Starting server, listen at: http://{}:{}".format(host[0], host[1]))
    server.serve_forever()

