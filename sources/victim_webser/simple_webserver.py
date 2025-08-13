# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

data = {"result": "Hello"}
host = ("0.0.0.0", 8080)

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
    server = HTTPServer(host, Request)
    print("Starting server, listen at: {}:{}".format(host[0], host[1]))
    server.serve_forever()

