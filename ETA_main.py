import os
import subprocess
import multiprocessing
import time
import signal

ETA_MODEL_PATH = "/home/uh3ng/ETA_sys/deepPacket-TF"
CAPTURED_PATH = "/home/uh3ng/Bridge/pcaps"
INITIAL_CWD = os.getcwd()

tcpdump_cmd = "tcpdump -i eth0 -G 10 -w {}".format(os.path.join(CAPTURED_PATH, r"%Y_%m_%d-%H_%M_%S.pcap"))
eta_cmd = "python3 tfl_predict.py --ext_delegate /usr/lib/libvx_delegate.so --model_path ./output_dir/traff_model-uint8.tflite --pcap "

cap_pro = None
analy_pro = None

def term_handler(signum, frame):
    print("In PID: {}".format(os.getpid()))
    print("Stopping ...")
    os.killpg(os.getpgid(0), 9)

def clean_pcaps():
    if os.path.exists(CAPTURED_PATH):
        for f in os.listdir(CAPTURED_PATH):
            os.remove(os.path.join(CAPTURED_PATH, f))
    else:
        os.mkdir(CAPTURED_PATH)
    return

def start_capture():
    p = subprocess.Popen(tcpdump_cmd, shell=True)
    print("CAPTURE PID: {}, PGID: {}".format(p.pid, os.getpgid(p.pid)))
    return p

def stop_capture(p):
    p.terminate()

# 每次循环取修改时间最晚的两个包，开始分析倒数第二个包
def analysis_pkt_loop():
    processed_files = []
    while True:
        pcaps = os.listdir(CAPTURED_PATH)
        pcaps.sort()
        if len(pcaps) >= 3 and pcaps[-3] not in processed_files:
            pcap_file = pcaps[-3]
            os.chdir(ETA_MODEL_PATH)
            cmd = eta_cmd + os.path.join(CAPTURED_PATH, pcap_file)
            print("ETA start: {}".format(cmd))
            p = subprocess.Popen(cmd, shell=True)
            print("DEEPPACKET PID: {}, GPID: {}".format(p.pid, os.getpgid(p.pid)))
            p.wait()
            processed_files.append(pcap_file)
        time.sleep(2)
    

if __name__ == '__main__':

    signal.signal(signal.SIGINT, term_handler)
    signal.signal(signal.SIGTERM, term_handler)

    clean_pcaps()
    cap_pro = start_capture()
    analy_pro = multiprocessing.Process(target=analysis_pkt_loop)
    analy_pro.start()
    print("ANALY PID: {}, PGID: {}".format(analy_pro.pid, os.getpgid(analy_pro.pid)))
    print("CURRENT PID: {}, PGID: {}".format(os.getpid(), os.getpgid(0)))

