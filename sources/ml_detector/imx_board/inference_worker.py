# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

from board_inference import LucidCNNBoardModel, SimpleDNNBoardModel

def run_inference_worker(model_name, model_path, input_shape, ready_flows, ret_queue):
    if model_name == "lucid_cnn":
        model = LucidCNNBoardModel(model_path, input_shape)
    elif model_name == "simple_dnn":
        model = SimpleDNNBoardModel(model_path, input_shape)
    else:
        return
    
    model_ret = model.detect(ready_flows)
    ret_queue.put(model_ret)
