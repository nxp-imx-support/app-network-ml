# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

# Run this test on the board

import numpy as np
from imx_board.board_inference import ModelInference
from imx_board.util_functions import load_dataset, calculate_metrics
import time

MODEL_PATH = "LUCID-ddos-CIC2019-quant-int8-imx943-npu.tflite"
EXT_DELEGATE_PATH = "/usr/lib/libneutron_delegate.so"
DATA_SIZE = 100

# If we do not use NPU model
# args.model = "LUCID-ddos-CIC2019-quant-int8.tflite"
# args.ext_delegate = None
# end if

x_data, y_true = load_dataset("dataset_test.hdf5")

if DATA_SIZE > 0:
    x_data = x_data[:DATA_SIZE]
    y_true = y_true[:DATA_SIZE]

model_inference = ModelInference(MODEL_PATH, (-1, 10, 11, 1))

t1 = time.time()
y_pred = model_inference.predict(x_data, EXT_DELEGATE_PATH)
t2 = time.time()

print(y_pred)
accuracy, precision, recall, f1, tp, fp, fn, tn = calculate_metrics(y_true, y_pred)


print("\n===== Evaluation Metrics =====")
print("Confusion Matrix:")
print("  TP: {}, FP: {}".format(tp, fp))
print("  FN: {}, TN: {}".format(fn, tn))
print("Accuracy:  {:.4f}".format(accuracy))
print("Precision: {:.4f}".format(precision))
print("Recall:    {:.4f}".format(recall))
print("F1 Score:  {:.4f}".format(f1))
print("inference time: {}s".format(t2 - t1))
