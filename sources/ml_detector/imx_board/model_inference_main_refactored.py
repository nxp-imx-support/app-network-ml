#!/usr/bin/env python3
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# DEPRECATED: This file references an incomplete inference_pool design.
# Use detector_main.py instead which implements ModelInferencePool.

import argparse
import signal
import time
import json
from collections import deque
from socket_ipc import SocketIPC, DetectionResult
from feature_converter import prepare_time_window
from board_inference import inference_pool, ModelInference

quit_flag = False
report_log = {"infer_time": 0, "total_packets": 0, "attacks_detected": 0}

def signal_handler(sig, frame):
    global quit_flag
    quit_flag = True

def main():
    global quit_flag, report_log

    parser = argparse.ArgumentParser(description='XDP-based inference')
    parser.add_argument('-m', '--model', required=True, help='TFLite model path')
    parser.add_argument('--model_id', default='lucid_cnn', help='Model ID')
    parser.add_argument('-e', '--ext_delegate', help='NPU delegate library')
    parser.add_argument('-s', '--socket', default='/tmp/imx-ddb-socket', help='Unix socket path')
    args = parser.parse_args()

    # Register models
    inference_pool.register("lucid_cnn", ModelInference("LUCID-CNN", time_window=10))
    inference_pool.register("simple_dnn", ModelInference("Simple-DNN", time_window=10))
    inference_pool.set_active(args.model_id)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    ipc = SocketIPC(args.socket)
    print(f"Connecting to {args.socket}...")
    ipc.connect()
    print("Connected to XDP controller")

    packet_buffer = deque(maxlen=10)

    while not quit_flag:
        try:
            packet = ipc.recv_packet_feature()
            packet_buffer.append(packet)
            report_log["total_packets"] += 1

            if len(packet_buffer) >= 10:
                x_data = prepare_time_window(list(packet_buffer))

                ts1 = time.time()
                model = inference_pool.get_active_model()
                predictions = model.predict(args.model, x_data, args.ext_delegate)
                ts2 = time.time()

                report_log["infer_time"] = ts2 - ts1

                is_attack = int(predictions[0])
                if is_attack:
                    report_log["attacks_detected"] += 1

                result = DetectionResult(
                    timestamp=int(time.time() * 1000000),
                    is_attack=is_attack,
                    confidence=95 if is_attack else 5,
                    flow_id=0
                )
                ipc.send_detection_result(result)

                with open("model_infer_report.json", "w") as f:
                    json.dump(report_log, f)

        except Exception as e:
            print(f"Error: {e}")
            break

    ipc.close()
    print("Inference process stopped")

if __name__ == '__main__':
    main()

