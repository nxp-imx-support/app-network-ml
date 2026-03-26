# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import signal
import logging
from collections import deque

from socket_ipc import SocketIPC, DetectionResult
from board_inference import ModelInferencePool, LucidCNNBoardModel, SimpleDNNBoardModel

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = "/tmp/imx_ddb.socket"

MODEL_CONFIGS = {
    "lucid_cnn": {
        "class": LucidCNNBoardModel,
        "path": "output/LUCID-ddos-CIC2019-quant-int8.tflite",
        "window_size": 10,
    },
    "simple_dnn": {
        "class": SimpleDNNBoardModel,
        "path": "output/simple-dnn-quant-int8.tflite",
        "window_size": 10,
    },
}


class DDoSDetector:
    def __init__(self, socket_path, model_name):
        self.socket_path = socket_path
        self.model_name = model_name
        self.running = False
        self.window_size = MODEL_CONFIGS[model_name]["window_size"]

        self.ipc = SocketIPC(socket_path)
        self.model_pool = ModelInferencePool()

        self._setup_models()
        self._setup_signal_handlers()

    def _setup_models(self):
        for name, config in MODEL_CONFIGS.items():
            self.model_pool.register(
                name,
                config["class"],
                config["path"],
                window_size=config["window_size"]
            )
        self.model_pool.set_active(self.model_name)
        logger.info("Active model: %s", self.model_name)

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        self.running = False

    def run(self):
        self.ipc.connect()
        logger.info("Connected to socket: %s", self.socket_path)

        packet_buffer = deque(maxlen=self.window_size)
        self.running = True
        flow_id = 0

        while self.running:
            try:
                packet = self.ipc.recv_packet_feature()
                packet_buffer.append(packet)

                if len(packet_buffer) >= self.window_size:
                    is_attack, confidence = self.model_pool.detect(packet_buffer)

                    result = DetectionResult(
                        timestamp=packet.timestamp,
                        is_attack=is_attack,
                        confidence=confidence,
                        flow_id=flow_id
                    )
                    self.ipc.send_detection_result(result)
                    flow_id += 1

            except ConnectionError as e:
                logger.error("Connection error: %s", e)
                break
            except Exception as e:
                logger.error("Error during inference: %s", e)
                continue

        self.ipc.close()
        logger.info("Detector stopped")


def main():
    parser = argparse.ArgumentParser(description="ML-based DDoS attack detector")
    parser.add_argument(
        "--model",
        type=str,
        default="lucid_cnn",
        choices=list(MODEL_CONFIGS.keys()),
        help="Model to use for inference"
    )
    parser.add_argument(
        "--socket-path",
        type=str,
        default=DEFAULT_SOCKET_PATH,
        help="Unix socket path for IPC with DPDK app"
    )

    args = parser.parse_args()

    detector = DDoSDetector(
        socket_path=args.socket_path,
        model_name=args.model
    )
    detector.run()


if __name__ == "__main__":
    main()
