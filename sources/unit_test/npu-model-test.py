import numpy as np
from model_inference_main import model_predict
from util_functions import load_dataset
import time

class test_args(object):
    def __init__(self):
        self.model = "LUCID-ddos-CIC2019-quant-int8-imx943-npu.tflite"
        self.ext_delegate = "/usr/lib/libneutron_delegate.so"
        self.ext_opt = {}

args = test_args()
# If we do not use NPU model
# args.model = "LUCID-ddos-CIC2019-quant-int8.tflite"
# args.ext_delegate = None
# end if

x_data, y_true = load_dataset("dataset_test.hdf5")

x_data = x_data[:100]
# print(x_data)

t1 = time.time()
Y_pred = model_predict(args, x_data)
t2 = time.time()
print(Y_pred)
print("delta time: {}s".format(t2 - t1))
