import struct
import signal
import os
import time
import select
import argparse
import numpy as np
import tflite_runtime.interpreter as tflite

class ArrayDesc(object):
    def __init__(self) -> None:
        self.row = 0
        self.col = 0

pipe_reader = "/tmp/cpp_to_py"
pipe_writer = "/tmp/py_to_cpp"
quit_flag = False
UINT64_SIZE = 8
DOUBLE_SIZE = 8
TIME_WIN_SIZE = 10
# 1 second
time_period = 1
inference_no = 1

LOG_LEVEL_INFO = 0x01
LOG_LEVEL_DEBUG = 0x02
LOG_LEVEL_ERROR = 0x04

G_LOG_LEVEL = (LOG_LEVEL_DEBUG | LOG_LEVEL_INFO | LOG_LEVEL_ERROR)

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
        log_info("handle exit signal... bye.")
        quit_flag = True

def unpack_double_type_array(array_desc, buf):
    log_debug("buf length: {}".format(len(buf)))
    ret = list()
    row_size = array_desc.col * DOUBLE_SIZE
    fmt_str = 'd' * array_desc.col
    for row_idx in range(array_desc.row):
        tmp = list(struct.unpack(fmt_str, buf[row_idx * row_size:(row_idx + 1) * row_size]))
        ret.append(tmp)
    return ret

def pack_double_type_array(array_desc, arr):
    ret = b''
    fmt_str = 'd'
    # One dimensional array
    for col_idx in range(array_desc.col):
        ret += struct.pack(fmt_str, arr[col_idx])
    return ret

def model_predict(args, x_data):
    global inference_no
    log_file = open("./inference-{}.txt".format(inference_no), "w")
    inference_no += 1
    log_file.write("x_data: \n{}\n".format(x_data))

    if args.model is not None:
        model_path = args.model
    else:
        log_error("No valid model specified!")
        return None
    
    ext_dele = None
    if args.ext_delegate is not None:
        log_info("Loading external delegate from {} with options: {}".format(args.ext_delegate, args.ext_opt))
        ext_dele = [tflite.load_delegate(args.ext_delegate, args.ext_opt)]
    model = tflite.Interpreter(model_path=model_path, experimental_delegates=ext_dele)
    model.allocate_tensors()

    input_desc = model.get_input_details()[0]
    output_desc = model.get_output_details()[0]
    input_scale, input_zero_point = input_desc['quantization']

    log_file.write("input_desc_type: {}, input_scale: {}, input_zero_point: {}\n".format(
        input_desc['dtype'], input_scale, input_zero_point
    ))

    # format the input shape
    x_data = np.array(x_data)
    log_debug("x_data shape: {}".format(x_data.shape))
    log_file.write("x_data shape: {}\n".format(x_data.shape))
    x_data = x_data.reshape((-1, TIME_WIN_SIZE, 11, 1))
    
    # warming up the model (necessary for the GPU)
    # cnt = 0
    # for vec in x_data:
    #     if cnt > 10 or cnt >= sample_len:
    #         break
    #     input_data = vec / input_scale + input_zero_point
    #     input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
    #     model.set_tensor(input_desc['index'], input_data)
    #     model.invoke()
    #     tmp = np.squeeze(model.get_tensor(output_desc['index']))
    #     tmp = input_scale * (tmp - input_zero_point)
    #     cnt += 1

    # Start inference
    Y_pred = list()
    avg_time = 0
    delta = 0
    
    for vec in x_data:
        input_data = np.expand_dims(vec, axis=0).astype(input_desc["dtype"])
        model.set_tensor(input_desc['index'], input_data)
        pt0 = time.time()
        model.invoke()
        delta = time.time() - pt0
        tmp = np.squeeze(model.get_tensor(output_desc['index']))
        Y_pred.append(1.0 if tmp != 0 else 0.0)
        avg_time += delta
    Y_pred = np.array(Y_pred)

    log_file.close()
    return Y_pred


def main():
    global quit_flag
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

    # fake_data = np.random.randn(100, 11).tolist()
    # print(model_predict(model_args, fake_data))
    # return

    global quit_flag
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGPIPE, signal_handler)

    ready_response = False
    array_desc = ArrayDesc()
    response_array = list()

    # Caution! Two open function call order must be this!
    writer_fd = os.open(pipe_writer, os.O_WRONLY)
    reader_fd = os.open(pipe_reader, os.O_RDONLY)
    log_debug("writer_fd: {}, reader_fd: {}".format(writer_fd, reader_fd))

    poll_fds = select.poll()
    poll_fds.register(reader_fd, select.POLLIN)
    poll_fds.register(writer_fd, select.POLLOUT)

    cur_ts = 0
    pre_ts = 0
    diff_ts = 1

    while quit_flag == False:
        cur_ts = time.time()
        diff_ts = cur_ts - pre_ts
        if diff_ts > time_period:
            pre_ts = cur_ts
            # poll timeout 10ms
            events = poll_fds.poll(100)
            for fd, flag in events:
                # log_debug("event come, fd: {}, flag: {}".format(fd, flag))
                if ready_response == False and fd == reader_fd and flag & select.POLLIN:
                    log_debug("Read from pipe...")
                    buf = os.read(fd, UINT64_SIZE * 2)
                    array_desc.row, array_desc.col = struct.unpack("QQ", buf)
                    log_debug("expected {} bytes to be read: row={}, col={}".format(array_desc.row * array_desc.col * DOUBLE_SIZE, array_desc.row, array_desc.col))
                    
                    left_bytes = array_desc.row * array_desc.col * DOUBLE_SIZE
                    tmp = b''
                    buf = b''
                    while left_bytes > 0 and quit_flag == False:
                        tmp = os.read(fd, 65536)
                        buf += tmp
                        left_bytes -= len(tmp)
                    if quit_flag:
                        break
                    # buf = os.read(fd, array_desc.row * array_desc.col * DOUBLE_SIZE)
                    x_data = unpack_double_type_array(array_desc, buf)
                    # print(x_data)
                    log_debug("Start model prediction.")
                    response_array = model_predict(model_args, x_data)
                    log_debug("Finish model prediction.")
                    if response_array is None:
                        quit_flag = True
                        break
                    ready_response = True
                    if quit_flag:
                        break

                if ready_response and fd == writer_fd and flag & select.POLLOUT:
                    log_debug("Prepare to write to pipe.")
                    array_desc.row = 1
                    array_desc.col = len(response_array)
                    log_debug("array row: {}, array col: {}".format(array_desc.row, array_desc.col))
                    desc_buf = struct.pack("QQ", array_desc.row, array_desc.col)
                    # log_debug("desc_buf: {}".format(desc_buf.hex()))
                    log_debug("response_array: {}".format(response_array))
                    buf = pack_double_type_array(array_desc, response_array)
                    os.write(fd, desc_buf)
                    os.write(fd, buf)
                    ready_response = False
                    log_debug("Finish writing.")

    log_info("Clean up...")
    poll_fds.unregister(reader_fd)
    poll_fds.unregister(writer_fd)
    os.close(reader_fd)
    os.close(writer_fd)

if __name__ == '__main__':
    main()
