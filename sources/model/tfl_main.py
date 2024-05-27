import struct
import signal
import os
import time

fifo_reader = "/tmp/dpdk_fifo"
fifo_writer = "/tmp/tfl_fifo"
quit_flag = False
DOUBLE_SIZE = 8

CTL_DOUBLE_VECTOR_START = 0x1
CTL_DOUBLE_VECTOR_END = 0x2
CTL_ECHO = 0x3

def term_handler(signum, frame):
    global quit_flag
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        print("handle exit signal... bye.")
        quit_flag = True
        exit(0)

def recv_control_message():
    with open(fifo_reader, 'rb') as fifo_file:
        buf = fifo_file.read()
    msg = int(buf[0])
    print(msg)
    return msg

def recv_vector_double():
    ret = list()
    with open(fifo_reader, 'rb') as fifo_file:
        buf = fifo_file.read()
    for i in range(0, len(buf), DOUBLE_SIZE):
        print(buf[i:i + DOUBLE_SIZE])
        tmp = struct.unpack('d', buf[i:i + DOUBLE_SIZE])[0]
        ret.append(tmp)
    return ret

def send_control_message():
    with open(fifo_writer, 'wb') as fifo_file:
        fifo_file.write(struct.pack('b', CTL_ECHO))
    print("send ctl msg.")
    return

def main():
    global quit_flag
    signal.signal(signal.SIGINT, term_handler)
    signal.signal(signal.SIGTERM, term_handler)

    if not os.path.exists(fifo_writer):
        os.mkfifo(fifo_writer)

    feature_vec = list()
    while quit_flag == False:
        # Expect to handle control message
        msg = recv_control_message()
        # Expect to recv double type vector from cpp
        if msg == CTL_DOUBLE_VECTOR_START:
            print("ready recv vector")
            send_control_message()
            l = recv_vector_double()
            feature_vec.append(l)
            send_control_message()
        elif msg == CTL_DOUBLE_VECTOR_END:
            print(feature_vec)
            send_control_message()
            # TODO Call AI inference function

            # Clear feature_vec
            feature_vec = list()
            continue
        else:
            print("Unexpected message: {}".format(msg))
            break


if __name__ == '__main__':
    main()