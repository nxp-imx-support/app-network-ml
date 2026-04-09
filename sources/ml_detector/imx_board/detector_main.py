# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import signal
import time
import logging
import multiprocessing as mp
import tomllib
import os
from multiprocessing import Queue
from socket_ipc import SocketIPC, DetectionResult, ResultEntry
from flow_entry import FlowEntry
from inference_worker import run_inference_worker

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "detector.toml")
with open(_CONFIG_PATH, "rb") as f:
    _CONFIG = tomllib.load(f)

DEFAULT_SOCKET_PATH = _CONFIG["default"]["socket_path"]
INFERENCE_INTERVAL = _CONFIG["default"]["inference_interval"]
PACKET_TIMEOUT = _CONFIG["default"]["packet_timeout"]
PACKET_TIMEOUT = PACKET_TIMEOUT * 1_000_000_000  # Convert to nanoseconds
IPC_TIMEOUT = _CONFIG["default"]["ipc_timeout"]
MAX_BATCH_SIZE = _CONFIG["default"]["max_batch_size"]

MODEL_CONFIGS = {
    name: {
        "path": cfg["path"],
        "input_shape": tuple(cfg["input_shape"]),
    }
    for name, cfg in _CONFIG["models"].items()
}

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class DDoSDetector:
    def __init__(self, socket_path, model_name, ext_delegate=None):
        self.socket_path = socket_path
        self.model_name = model_name
        self.ext_delegate = ext_delegate
        self.running = False

        config = MODEL_CONFIGS[model_name]
        self.model_path = config["path"]
        self.input_shape = config["input_shape"]

        self.ipc = SocketIPC(socket_path)
        self.flow_table = list()
        self.flow_id_num = 0

        self._proc = None
        self._result_queue = Queue()

        self.total_pkt = 0

        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        self.running = False

    def _update_flow_table(self, pkt):
        # Make flow key
        pkt_flow_key = None
        if pkt.src_port < pkt.dst_port:
            pkt_flow_key = (pkt.l4_type, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        elif pkt.src_port == pkt.dst_port and pkt.src_ip < pkt.dst_ip:
            pkt_flow_key = (pkt.l4_type, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        else:
            pkt_flow_key = (pkt.l4_type, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        
        new_flow = True
        # logger.debug("Processing packet for flow key: %s", pkt_flow_key)
        for flow_entry in self.flow_table:
            if flow_entry.flow_key == pkt_flow_key:
                flow_entry.packets.append(pkt)
                new_flow = False
                break
        
        if new_flow:
            self.flow_table.append(FlowEntry(self.flow_id_num, pkt_flow_key, pkt))
            self.flow_id_num += 1

    def _lookup_flow_tuple_by_flow_id(self, flow_id):
        for flow_entry in self.flow_table:
            if flow_entry.flow_id == flow_id:
                return flow_entry.flow_key
        return None

    def _get_ready_flows(self):
        # Get the boot time in nanoseconds
        cur_ts = time.monotonic_ns()
        ready_flows = list()
        for flow_entry in self.flow_table:
            if flow_entry.is_ready and cur_ts - flow_entry.first_packet_time >= PACKET_TIMEOUT:
                ready_flows.append(flow_entry)
                flow_entry.is_ready = False
        return ready_flows

    def run(self):
        self.ipc.connect()
        logger.info("Connected to socket: %s", self.socket_path)
        logger.info("Model: %s (%s)", self.model_name, self.model_path)

        self.running = True
        last_inference_time = time.time()

        while self.running:
            packet = self._process_incoming_packets()
            if packet is None:
                continue
            
            self.total_pkt += 1
            self._reap_completed_proc()

            if time.time() - last_inference_time >= INFERENCE_INTERVAL:
                if self._proc is None:
                    self._trigger_inference()
                    last_inference_time = time.time()
                else:
                    logger.info("Skipping inference, previous not complete")

        self._cleanup()
        logger.info("Detector stopped")

    def _reap_completed_proc(self):
        detect_ret = DetectionResult()

        if self._proc is not None and not self._proc.is_alive():
            self._proc.join()
            self._proc = None
            if not self._result_queue.empty():
                result_array = self._result_queue.get()
                if len(result_array) == 0:
                    logger.warning("Empty result array from inference")
                else:
                    for item in result_array:
                        flow_id = item[0]
                        is_attack = item[1]
                        confidence = item[2]
                        flow_key = self._lookup_flow_tuple_by_flow_id(flow_id)
                        if flow_key is not None:
                            detect_ret.append_new_ret_entry(ResultEntry(
                                flow_key[0], flow_key[1], flow_key[2],
                                flow_key[3], flow_key[4], is_attack, confidence))
                        else:
                            logger.warning("Flow ID %d not found in flow table", flow_id)

        try:
            # logger.debug("Prepare to send detection results: {} entries, total packets: {}".format(detect_ret.ret_size, self.total_pkt))
            self.ipc.send_detection_result(detect_ret)
        except (ConnectionError, BrokenPipeError) as e:
            logger.info("Peer closed connection: %s", e)
            self.running = False

    def _process_incoming_packets(self):
        """Receive packets and update flow table"""
        try:
            packet = self.ipc.recv_packet_feature(timeout=IPC_TIMEOUT)
            if packet is None:
                return None
            self._update_flow_table(packet)
            return packet
        except ConnectionError as e:
            logger.error("Connection error: %s", e)
            self.running = False
            return None
        except Exception as e:
            logger.error("Error processing packet: %s", e)
            return None

    def _trigger_inference(self):
        """Collect ready flows and spawn inference subprocess"""
        ready_flows = self._get_ready_flows()

        if len(ready_flows) == 0:
            logger.debug("No ready flows for inference")
            return

        logger.info("Starting inference for %d flows", len(ready_flows))

        self._proc = mp.Process(
            target=run_inference_worker,
            args=(self.model_name, self.model_path, self.input_shape, ready_flows, self._result_queue)
        )
        self._proc.start()
        logger.info("Start inference process with PID: {}".format(self._proc.pid))

    def _cleanup(self):
        """Cleanup resources before exit"""
        logger.info("Cleaning up detector resources")
        if self._proc is not None and self._proc.is_alive():
            self._proc.terminate()
            self._proc.join()

        try:
            self.ipc.close()
        except Exception:
            pass


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
    parser.add_argument(
        "--ext-delegate",
        type=str,
        default=None,
        help="NPU delegate library path (e.g., libethosu.so)"
    )

    args = parser.parse_args()

    detector = DDoSDetector(
        socket_path=args.socket_path,
        model_name=args.model,
        ext_delegate=args.ext_delegate
    )
    detector.run()

if __name__ == "__main__":
    main()
