# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
# 
# Invoke quantized model on board.
# Do not run this script on Linux host.

import struct
import signal
import os
import time
import select
import argparse
import numpy as np
import tflite_runtime.interpreter as tflite
import json
import posix_ipc
import ctypes

class ArrayDesc(object):
    def __init__(self) -> None:
        self.row = 0
        self.col = 0

sem0 = "/semaphore0"
sem1 = "/semaphore1"

quit_flag = False
SHM_SIZE = 5 * 1024 * 1024
UINT64_SIZE = 8
DOUBLE_SIZE = 8
TIME_WIN_SIZE = 10
# i.MX943 NPU only supports BATCH_SIZE = 1
BATCH_SIZE = 1
# 1 second
time_period = 1
inference_no = 1

LOG_LEVEL_INFO = 0x01
LOG_LEVEL_DEBUG = 0x02
LOG_LEVEL_ERROR = 0x04

G_LOG_LEVEL = (LOG_LEVEL_DEBUG | LOG_LEVEL_INFO | LOG_LEVEL_ERROR)

report_log = dict()
MODEL_INFERENCE_REPORT_PATH = "./model_infer_report.json"

def log_print(log_level, log_message):
    if log_level & G_LOG_LEVEL:
        print(log_message)

def log_debug(log_message):
    log_message = "[DEBUG] " + log_message
    log_print(LOG_LEVEL_DEBUG, log_message)

def log_error(log_message):
    log_message = "[ERROR] " + log_message
    log_print(LOG_LEVEL_ERROR, log_message)

def log_info(log_message):
    log_message = "[INFO] " + log_message
    log_print(LOG_LEVEL_INFO, log_message)
          

def signal_handler(signum, frame):
    global quit_flag
    if signum == signal.SIGINT or signum == signal.SIGTERM or signum == signal.SIGPIPE:
        log_info("signal {} recv. handle exit signal... bye.".format(signum))
        quit_flag = True

def unpack_double_type_array(array_desc, buf):
    log_debug("buf length: {}".format(len(buf)))
    ret = np.frombuffer(buf, np.float64)
    ret.reshape(array_desc.row, array_desc.col)
    return ret

def pack_double_type_array(array_desc, arr):
    ret = b''
    fmt_str = 'd'
    # One dimensional array
    for col_idx in range(array_desc.col):
        ret += struct.pack(fmt_str, arr[col_idx])
    return ret

def quantify_float_to_int8(data, scale, zero_point):
    ret_data = data.astype(np.float32)
    ret_data = np.round(ret_data / scale + zero_point)
    ret_data = np.clip(ret_data, -128, 127).astype(np.int8)
    return ret_data

def inverse_quant_int8_to_float(data, scale, zero_point):
    ret_data = (data.astype(np.float32) - zero_point) * scale
    return ret_data

def model_predict(args, x_data):
    global inference_no
    global report_log
    # log_file = open("./inference-{}.txt".format(inference_no), "w")
    inference_no += 1
    # log_file.write("x_data: \n{}\n".format(x_data))

    if args.model is not None:
        model_path = args.model
    else:
        log_error("No valid model specified!")
        return None
    
    ext_dele = None
    if args.ext_delegate is not None:
        log_info("Loading external delegate from {} with options: {}".format(args.ext_delegate, args.ext_opt))
        ext_dele = [tflite.load_delegate(args.ext_delegate, args.ext_opt)]
        report_log["npu_used"] = 1

    # format the input shape
    # x_data = np.array(x_data)
    log_debug("x_data shape: {}".format(x_data.shape))
    # log_file.write("x_data shape: {}\n".format(x_data.shape))
    x_data = x_data.reshape((-1, TIME_WIN_SIZE, 11, 1))
    report_log["infer_samples"] = x_data.shape[0]
    log_info("Samples number: {}".format(x_data.shape[0]))
    model = tflite.Interpreter(model_path=model_path, experimental_delegates=ext_dele)
    input_desc = model.get_input_details()[0]
    output_desc = model.get_output_details()[0]

    log_info("Model name: {}".format(os.path.basename(model_path)))
    log_info(f"Input dtype: {input_desc['dtype']}")
    log_info(f"Input quantization: scale={input_desc['quantization'][0]}, zero_point={input_desc['quantization'][1]}")
    log_info(f"Output dtype: {output_desc['dtype']}")
    log_info(f"Output quantization: scale={output_desc['quantization'][0]}, zero_point={output_desc['quantization'][1]}")

    input_scale = input_desc['quantization'][0]
    input_zero_point = input_desc['quantization'][1]
    output_scale = output_desc['quantization'][0]
    output_zero_point = output_desc['quantization'][1]

    if BATCH_SIZE > 1:
        model.resize_tensor_input(input_desc['index'], [BATCH_SIZE, x_data.shape[1], x_data.shape[2], x_data.shape[3]])
    model.allocate_tensors()

    Y_pred = list()
    # Start inference    
    # Batch input
    if BATCH_SIZE > 1:
        batch_offset = 0
        batchs = int(x_data.shape[0] / BATCH_SIZE)
        left = x_data.shape[0] % BATCH_SIZE
        if left > 0:
            batchs += 1
            padding_num = BATCH_SIZE - left
        padding_vector = np.zeros((padding_num, x_data.shape[1], x_data.shape[2], x_data.shape[3]))
        x_data = np.concatenate((x_data, padding_vector), axis=0)
        for b in range(batchs):
            input_data = x_data[batch_offset:batch_offset+BATCH_SIZE]
            input_data = quantify_float_to_int8(input_data, input_scale, input_zero_point)
            batch_offset += BATCH_SIZE
            print("debug in batch")
            model.set_tensor(input_desc['index'], input_data)
            model.invoke()
            output_list = model.get_tensor(output_desc['index'])
            output_list = inverse_quant_int8_to_float(output_list, output_scale, output_zero_point)
            log_debug("output_list shape: {}".format(output_list.shape))
            for tmp in output_list:
                if tmp[0] >= 0.5:
                    Y_pred.append(1.0)
                else:
                    Y_pred.append(0.0)
        if padding_num != 0:
            Y_pred = Y_pred[:-padding_num]
    # Single input
    else:
        for vec in x_data:
            input_data = np.expand_dims(vec, axis=0)
            input_data = quantify_float_to_int8(input_data, input_scale, input_zero_point)
            model.set_tensor(input_desc['index'], input_data)
            model.invoke()
            output = model.get_tensor(output_desc['index'])
            output = inverse_quant_int8_to_float(output, output_scale, output_zero_point)
            output = np.squeeze(output)
            Y_pred.append(1.0 if output >= 0.5 else 0.0)

    Y_pred = np.array(Y_pred)
    # log_file.close()
    return Y_pred


def main():
    global quit_flag, report_log
    # Create shared memory and semaphore.
    sem_0 = posix_ipc.Semaphore(sem0, posix_ipc.O_CREAT, initial_value=0)
    sem_1 = posix_ipc.Semaphore(sem1, posix_ipc.O_CREAT, initial_value=0)

    shm_lib = ctypes.CDLL("../libshmanager.so")

    shm_lib.create_shm_block.restype = ctypes.c_int

    shm_lib.read_frm_shm.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    shm_lib.read_frm_shm.restype = ctypes.c_int

    shm_lib.write_to_shm.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    shm_lib.write_to_shm.restype = ctypes.c_int

    sem_1.release()
    sem_0.acquire()
    shm_id = shm_lib.create_shm_block(4 * 1024)
    if shm_id < 0:
        log_error("Create shared memory failed.")
        return
    # End of create shared memory and semaphore.
    
    parser = argparse.ArgumentParser(
        description='DDoS attacks detection with convolutional neural networks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-m', '--model', type=str,
                        help='File containing the model')
    parser.add_argument(
      '-e', '--ext_delegate', help='external_delegate_library path')
    parser.add_argument(
      '-o',
      '--ext_opt',
      help='external delegate options, \
            format: "option1: value1; option2: value2"')
    model_args = parser.parse_args()
    print("model_args: ", model_args)

    global quit_flag
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGPIPE, signal_handler)


    msg_desc_size = UINT64_SIZE * 2
    array_desc = ArrayDesc()
    response_array = list()

    # Let dpdk-l2capfwd know it can raise a inference request.
    sem_1.release()

    while quit_flag == False:
        try:
            sem_0.acquire(timeout=1)
        except posix_ipc.BusyError:
            continue
        except posix_ipc.SignalError:
            continue
        
        # if status == False:
        #     continue

        log_debug("Read from shared memory...")
        ts_start = time.time()
        expected_data_length = msg_desc_size
        buf = bytes(expected_data_length)
        shm_lib.read_frm_shm(shm_id, 0, expected_data_length, buf)
        array_desc.row, array_desc.col = struct.unpack("QQ", buf)
        log_debug("expected {} bytes to be read: row={}, col={}".format(expected_data_length, array_desc.row, array_desc.col))
        
        expected_data_length = array_desc.row * array_desc.col * DOUBLE_SIZE
        log_debug("expected {} bytes to be read".format(expected_data_length))
        buf = bytes(expected_data_length)
        read_offset = 0
        shm_max_buf_size = SHM_SIZE - msg_desc_size
        sem_0.release()
        while read_offset < expected_data_length:
            sem_0.acquire()
            actual_read_bytes = min(expected_data_length - read_offset, shm_max_buf_size)
            shm_lib.read_frm_shm(shm_id, msg_desc_size, actual_read_bytes, buf[read_offset:])
            log_debug("Read {} bytes from shared memory".format(actual_read_bytes))
            read_offset += actual_read_bytes
            sem_1.release()
        if quit_flag:
            break
        # buf = os.read(fd, array_desc.row * array_desc.col * DOUBLE_SIZE)
        ts_checkpoint1 = time.time()
        x_data = unpack_double_type_array(array_desc, buf)
        ts_checkpoint2 = time.time()
        # print(x_data)
        log_debug("Start model prediction.")
        model_ts1 = time.time()
        response_array = model_predict(model_args, x_data)
        model_ts2 = time.time()
        report_log["infer_time"] = model_ts2 - model_ts1
        log_info("Inference time: {}s".format(report_log["infer_time"]))
        with open(MODEL_INFERENCE_REPORT_PATH, "w") as fd:
            fd.write(json.dumps(report_log))
        log_debug("Finish model prediction.")
        tot_time = time.time() - ts_start
        log_info("Handle time: {}s. Shared memory read time: {}s, Receive time: {}s.".format(tot_time, ts_checkpoint1 - ts_start, ts_checkpoint2 - ts_start))
        if response_array is None:
            quit_flag = True
            break
        if quit_flag:
            break

        log_debug("Write to shared memory.")
        array_desc.row = 1
        array_desc.col = len(response_array)
        log_debug("array row: {}, array col: {}".format(array_desc.row, array_desc.col))
        # Write msg_desc firstly
        buf = struct.pack("QQ", array_desc.row, array_desc.col)
        shm_lib.write_to_shm(shm_id, 0, msg_desc_size, buf)
        # Write array
        log_debug("response_array: {}".format(response_array))
        buf = pack_double_type_array(array_desc, response_array)
        send_bytes = array_desc.row * array_desc.col * DOUBLE_SIZE
        shm_max_buf_size = SHM_SIZE - msg_desc_size
        send_offset = 0
        while send_offset < send_bytes:
            actual_write_bytes = min(send_bytes - send_offset, shm_max_buf_size)
            shm_lib.write_to_shm(shm_id, msg_desc_size, actual_write_bytes, buf[send_offset:])
            log_debug("{} bytes to write.".format(actual_write_bytes))
            send_offset += actual_write_bytes
            sem_1.release()
            sem_0.acquire()
        
        log_debug("Finish writing.")
        sem_1.release()

    log_info("Clean up...")
    sem_0.close()
    sem_1.close()

if __name__ == '__main__':
    main()
