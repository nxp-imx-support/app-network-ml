# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import numpy as np
import os
import struct
import tflite_runtime.interpreter as tflite
from abc import ABC, abstractmethod

# Model status retured to caller
class ModelRetStatus:
    # With a valid detection result
    M_STAT_OK = 0x00
    # With a 
    M_STAT_NEED_MORE_PACKETS = 0x01

class BaseBoardModel(ABC):
    """Abstract base class for board-side TFLite models"""

    def __init__(self, model_path, input_shape):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        self.model_path = model_path
        self.model_name = os.path.basename(model_path)
        self.input_shape = input_shape
        self._interpreter = None
        self._input_desc = None
        self._output_desc = None

    def _packet_features_to_array(self, packets):
        """Convert list of PacketFeature to numpy array (11 features per packet)"""
        features_list = []
        for packet in packets[-self.window_size:]:
            features = np.zeros(11, dtype=np.float32)
            features[0] = packet.protocol_type
            features[1] = packet.src_ip
            features[2] = packet.dst_ip
            features[3] = packet.transmission_type
            features[4] = packet.src_port
            features[5] = packet.dst_port
            features[6] = packet.packet_size
            features[7] = packet.tcp_flags
            features[8] = int.from_bytes(packet.src_mac[:4], 'big')
            features[9] = int.from_bytes(packet.dst_mac[:4], 'big')
            features[10] = packet.timestamp & 0xFFFFFFFF
            features_list.append(features)

        while len(features_list) < self.window_size:
            features_list.insert(0, np.zeros(11, dtype=np.float32))

        return np.array(features_list, dtype=np.float32)

    @abstractmethod
    def preprocess(self, packet_buffer):
        """Convert packet buffer to model input tensor"""
        pass

    def predict(self, x_data, ext_delegate=None, ext_opt=None):
        """Run inference with TFLite model"""
        ext_dele = [tflite.load_delegate(ext_delegate, ext_opt)] if ext_delegate else None

        x_data = x_data.reshape(self.input_shape)

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

    def detect(self, packet_buffer):
        """Full detection pipeline: preprocess -> predict -> postprocess"""
        x_data = self.preprocess(packet_buffer)
        prediction = self.predict(x_data)
        return self.postprocess(prediction)


class LucidCNNBoardModel(BaseBoardModel):
    """LUCID CNN model for board-side inference (2D CNN, input_shape=(10, 11, 1))"""

    def __init__(self, model_path, window_size=10):
        super().__init__(model_path, window_size)

    @property
    def input_shape(self):
        return (self.window_size, 11, 1)

    def preprocess(self, packet_buffer):
        """Prepare time window for LUCID model: reshape to (window_size, 11, 1)"""
        features = self._packet_features_to_array(packet_buffer)
        return features.reshape(1, self.window_size, 11, 1)

    def postprocess(self, prediction):
        """Interpret LUCID CNN output: binary classification"""
        is_attack = int(prediction[0] >= 0.5)
        confidence = int(abs(prediction[0] - 0.5) * 200)
        return is_attack, confidence


class SimpleDNNBoardModel(BaseBoardModel):
    """Simple DNN model for board-side inference (flattened input, input_shape=(110,))"""

    def __init__(self, model_path, window_size=10):
        super().__init__(model_path, window_size)

    @property
    def input_shape(self):
        return (self.window_size * 11,)

    def preprocess(self, packet_buffer):
        """Prepare flattened input for Simple DNN: reshape to (110,)"""
        features = self._packet_features_to_array(packet_buffer)
        return features.reshape(1, self.window_size * 11)

    def postprocess(self, prediction):
        """Interpret Simple DNN output: binary classification (same threshold as LUCID)"""
        is_attack = int(prediction[0] >= 0.5)
        confidence = int(abs(prediction[0] - 0.5) * 200)
        return is_attack, confidence


class ModelInferencePool:
    """Manages multiple board models for inference"""

    def __init__(self):
        self._models = {}
        self._active_name = None

    def register(self, model_name, model_class, model_path, **kwargs):
        """Register a board model for inference"""
        self._models[model_name] = model_class(model_path, **kwargs)

    def set_active(self, model_name):
        """Set the active model for inference"""
        if model_name not in self._models:
            available = list(self._models.keys())
            raise ValueError(
                f"Model '{model_name}' not registered. Available: {available}"
            )
        self._active_name = model_name

    def get_active_model(self):
        """Get the currently active model"""
        if self._active_name is None:
            raise RuntimeError("No active model set. Call set_active() first.")
        return self._models[self._active_name]

    def detect(self, packet_buffer):
        """Run full detection pipeline on active model"""
        model = self.get_active_model()
        return model.detect(packet_buffer)

    def predict(self, x_data, ext_delegate=None, ext_opt=None):
        """Run inference on the active model (raw output)"""
        model = self.get_active_model()
        return model.predict(x_data, ext_delegate, ext_opt)

    def list_models(self):
        """Return list of registered model names"""
        return list(self._models.keys())
