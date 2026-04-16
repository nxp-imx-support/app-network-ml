# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import numpy as np
import os
from util_functions import PROTOCOL_NUM, normalize_num
import tflite_runtime.interpreter as tflite
from abc import ABC, abstractmethod

# TODO: Model status retured to caller
class ModelRetStatus:
    # With a valid detection result
    M_STAT_OK = 0x00
    # With a 
    M_STAT_NEED_MORE_PACKETS = 0x01

class BaseBoardModel(ABC):
    """Abstract base class for board-side TFLite models"""

    def __init__(self, model_path, input_shape, ext_delegate=None, ext_opt=None):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        self.model_path = model_path
        self.model_name = os.path.basename(model_path)
        self.input_shape = input_shape
        self.ext_delegate = ext_delegate
        self.ext_opt = ext_opt
        self.x_data = list()
        self.x_label = list()

    @abstractmethod
    def preprocess(self, ready_flows):
        """Convert packet buffer to model input tensor"""
        pass

    def predict(self, x_data):
        """Run inference with TFLite model"""
        ext_dele = [tflite.load_delegate(self.ext_delegate, self.ext_opt)] if self.ext_delegate else None

        interpreter = tflite.Interpreter(
            model_path=self.model_path,
            experimental_delegates=ext_dele
        )

        input_desc = interpreter.get_input_details()[0]
        output_desc = interpreter.get_output_details()[0]
        interpreter.allocate_tensors()

        input_scale = input_desc['quantization'][0]
        input_zero_point = input_desc['quantization'][1]
        output_scale = output_desc['quantization'][0]
        output_zero_point = output_desc['quantization'][1]

        Y_pred = []

        for vec in x_data:
            input_data = np.expand_dims(vec, axis=0)
            input_data = np.round(input_data / input_scale + input_zero_point)
            input_data = np.clip(input_data, -128, 127).astype(np.int8)

            interpreter.set_tensor(input_desc['index'], input_data)
            interpreter.invoke()

            output = interpreter.get_tensor(output_desc['index'])
            output = (output.astype(np.float32) - output_zero_point) * output_scale
            Y_pred.append(np.squeeze(output))

        return np.array(Y_pred)

    @abstractmethod
    def postprocess(self, prediction):
        """Interpret prediction -> (is_attack: int, confidence: int)"""
        pass

    def detect(self, flows):
        """Full detection pipeline: preprocess -> predict -> postprocess"""
        print("Start preprocess...")
        x_array, label_array = self.preprocess(flows)
        print("Start predict...")
        y_pred = self.predict(x_array)
        print("Start postprocess...")
        return self.postprocess(y_pred, label_array)


class LucidCNNBoardModel(BaseBoardModel):
    """LUCID CNN model for board-side inference (2D CNN, input_shape=(10, 11, 1))"""

    def __init__(self, model_path, input_shape, window_size=10):
        super().__init__(model_path, input_shape)
        self.window_size = window_size
        self.feature_value_range = [
            [0, 10],
            [0, 0xFFFF],
            [0, 0x0F],
            [0, 0xFFFF],
            [0, 0xFFFF],
            [0, 0xFFFF],
            [0, 0xFFFFFFFF],
            [0, 0xFFFF],
            [0, 0xFFFF],
            [0, 0xFFFF],
            [0, 0xFF]
        ]
    
    def _packet_features_to_array(self, base_packet, packet):
        """
        Convert packet object to a feature array of shape (11,)
        """

        features = np.zeros(11, dtype=np.float32)
        ts_diff = (packet.timestamp - base_packet.timestamp) / 1e+9 # Convert to secends
        features[0] = (self.feature_value_range[0][1] - ts_diff) / (self.feature_value_range[0][1] - self.feature_value_range[0][0])
        features[1] = normalize_num(packet.l2_length, 
                                    self.feature_value_range[1][0], self.feature_value_range[1][1])
        features[2] = normalize_num(packet.ip_flags, 
                                    self.feature_value_range[2][0], self.feature_value_range[2][1])
        features[3] = normalize_num(packet.l4_type, 
                                    self.feature_value_range[3][0], self.feature_value_range[3][1])            # Highest layer
        features[4] = normalize_num(packet.l3_type + packet.l4_type, 
                                    self.feature_value_range[4][0], self.feature_value_range[4][1])  # IP protocol

        # TCP len
        if packet.l4_type == PROTOCOL_NUM.PROTOCOL_TCP:
            features[5] = normalize_num(packet.l4_length,
                                        self.feature_value_range[5][0], self.feature_value_range[5][1])

        features[6] = normalize_num(packet.tcp_ack,
                                    self.feature_value_range[6][0], self.feature_value_range[6][1])        # tcp_ack
        features[7] = normalize_num(packet.tcp_flags,
                                    self.feature_value_range[7][0], self.feature_value_range[7][1])
        features[8] = normalize_num(packet.tcp_win,
                                    self.feature_value_range[8][0], self.feature_value_range[8][1])

        # UDP len
        if packet.l4_type == PROTOCOL_NUM.PROTOCOL_UDP:
            features[9] = normalize_num(packet.l4_length,
                                        self.feature_value_range[9][0], self.feature_value_range[9][1])
        
        features[10] = normalize_num(packet.icmp_type,
                                     self.feature_value_range[10][0], self.feature_value_range[10][1])
        # print("=" * 60)
        # print("packet features:")
        # print("diff_ts={}".format(ts_diff))
        # print("l2_length={}".format(packet.l2_length))
        # print("ip_flags={}".format(packet.ip_flags))
        # print("l4_type={}".format(packet.l4_type))
        # print("l3_type+l4_type={}".format(packet.l3_type + packet.l4_type))
        # print("tcp_length={}".format(packet.l4_length))
        # print("tcp_ack={}".format(packet.tcp_ack))
        # print("tcp_flags={}".format(packet.tcp_flags))
        # print("tcp_win={}".format(packet.tcp_win))
        # print("udp_len={}".format(packet.l4_length))
        # print("icmp_type={}".format(packet.icmp_type))
        # print("=" * 60)
        return features

    def _cut_flow_to_slices(self, packets):
        pkt_num = len(packets)
        if pkt_num == 0:
            return []
        
        pkt_seq = 0
        pkt_idx = 0
        now = 0
        start_ts = packets[0].timestamp
        flow_slices = list()
        time_win = list()
        win_time_period = 10    # 10 second time window

        while pkt_idx < pkt_num:
            # if pkt_idx % 20 == 0:
            #     print("In transfer_to_feature, pkt_idx: {}".format(pkt_idx))
            pkt = packets[pkt_idx]
            now = pkt.timestamp
            diff = (now - start_ts) / 1e+9

            # Require a new time window.
            if diff - win_time_period > 1e-6:
                # Padding last window
                while pkt_seq < self.window_size:
                    time_win.append(None)
                    pkt_seq += 1
                flow_slices.append(time_win)
                # New time window
                time_win = list()
                pkt_seq = 0
                start_ts = pkt.timestamp
                pkt_seq += 1
                time_win.append(pkt)
            else:
                # When a time window is full, do not push new packets until the diff > win_time_period
                if pkt_seq >= self.window_size:
                    pkt_idx += 1
                    continue
                time_win.append(pkt)
                pkt_seq += 1
            pkt_idx += 1

        # padding the last one
        while pkt_seq < self.window_size:
            time_win.append(None)
            pkt_seq += 1
        flow_slices.append(time_win)
        # Expect the shape (slice_cnt, 10)
        return flow_slices

    def _append_flow(self, flow_id, packets):
        flow_slices = self._cut_flow_to_slices(packets)
        for slice_item in flow_slices:
            slice_feature_vector = list()
            for idx, pkt in enumerate(slice_item):
                if pkt is None:
                    pkt_feature_vector = np.zeros(11, dtype=np.float32)
                else:
                    if idx == 0:
                        base_pkt = pkt
                    pkt_feature_vector = self._packet_features_to_array(base_pkt, pkt)
                slice_feature_vector.append(pkt_feature_vector)
            self.x_data.append(slice_feature_vector)
            self.x_label.append(flow_id)
        return

    def preprocess(self, ready_flows):
        self.x_data.clear()
        self.x_label.clear()
        
        for flow in ready_flows:
            self._append_flow(flow.flow_id, flow.packets)
        ret_x_data = np.array(self.x_data, dtype=np.float32)
        ret_x_data = ret_x_data.reshape(self.input_shape)
        ret_x_label = np.array(self.x_label, dtype=np.int32)

        return ret_x_data, ret_x_label

    def postprocess(self, prediction, label_array):
        """
        Interpret LUCID CNN output for multiple flows: binary classification per flow
        Args:
            prediction: 1D np.array of attack probabilities
            label_array: 1D np.array of flow_ids corresponding to each prediction
        Returns:
            List of (is_attack, confidence) tuples, one per unique flow_id
        """
        print("prediction result shape: {}".format(prediction.shape))
        print("label_array shape: {}".format(label_array.shape))
        unique_flow_ids = np.unique(label_array)
        results = []

        for flow_id in unique_flow_ids:
            flow_mask = label_array == flow_id
            flow_predictions = prediction[flow_mask]

            attack_count = np.sum(flow_predictions >= 0.5)
            total_count = len(flow_predictions)

            is_attack = int(attack_count > total_count / 2)

            avg_pred = np.mean(flow_predictions)
            confidence = int(abs(avg_pred - 0.5) * 200)

            results.append((flow_id, is_attack, confidence))

        return results


class SimpleDNNBoardModel(BaseBoardModel):
    """Simple DNN model for board-side inference (flattened input, input_shape=(110,))"""

    def __init__(self, model_path, window_size=10):
        super().__init__(model_path)
        self.window_size = window_size

    @property
    def input_shape(self):
        return (self.window_size * 11,)

    def preprocess(self, ready_flows):
        """Prepare flattened input for Simple DNN: reshape to (110,)"""
        pass

    def postprocess(self, prediction):
        """Interpret Simple DNN output: binary classification (same threshold as LUCID)"""
        is_attack = int(prediction[0] >= 0.5)
        confidence = int(abs(prediction[0] - 0.5) * 200)
        return is_attack, confidence

