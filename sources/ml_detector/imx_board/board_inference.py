# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Board-side inference module (uses tflite_runtime)

import numpy as np
import os
import tflite_runtime.interpreter as tflite

class ModelInference:
    """Base inference class for board-side TFLite models"""

    def __init__(self, model_path, input_shape=(-1, 10, 11, 1)):
        self.model_path = model_path
        self.input_shape = input_shape
        self.model_name = os.path.basename(model_path)

    def predict(self, x_data, ext_delegate=None, ext_opt=None):
        """Run inference with TFLite model"""
        ext_dele = [tflite.load_delegate(ext_delegate, ext_opt)] if ext_delegate else None

        x_data = x_data.reshape(self.input_shape)
        model = tflite.Interpreter(model_path=self.model_path, experimental_delegates=ext_dele)

        input_desc = model.get_input_details()[0]
        output_desc = model.get_output_details()[0]
        model.allocate_tensors()

        input_scale = input_desc['quantization'][0]
        input_zero_point = input_desc['quantization'][1]
        output_scale = output_desc['quantization'][0]
        output_zero_point = output_desc['quantization'][1]

        Y_pred = []
        for vec in x_data:
            input_data = np.expand_dims(vec, axis=0)
            input_data = np.round(input_data / input_scale + input_zero_point)
            input_data = np.clip(input_data, -128, 127).astype(np.int8)

            model.set_tensor(input_desc['index'], input_data)
            model.invoke()

            output = model.get_tensor(output_desc['index'])
            output = (output.astype(np.float32) - output_zero_point) * output_scale
            Y_pred.append(1.0 if np.squeeze(output) >= 0.5 else 0.0)

        return np.array(Y_pred)

