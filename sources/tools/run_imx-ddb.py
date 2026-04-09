import subprocess
import signal
import sys
import time

quit_flag = False

def handle_sigint(sig, frame):
    global quit_flag
    print("Capture Ctrl-C signal")
    quit_flag = True
    sys.exit(0)

def setup_network_bridge():
    port_0 = "swp0"
    port_1 = "eth1"
    bridge_name = "br0"

    p_ret = subprocess.run(f"ip link show {bridge_name}", shell=True)
    if p_ret.returncode == 0:
        print("Bridge already exists, removing")
        subprocess.run(f"ip link del {bridge_name}", shell=True)

    time.sleep(2)
    print("Creating bridge")
    subprocess.run(f"ip link add name {bridge_name} type bridge", shell=True)
    subprocess.run(f"ip link set dev {port_0} master {bridge_name}", shell=True)
    subprocess.run(f"ip link set dev {port_1} master {bridge_name}", shell=True)
    subprocess.run(f"ip link set {bridge_name} up", shell=True)
    subprocess.run(f"ip link set {port_0} up", shell=True)
    subprocess.run(f"ip link set {port_1} up", shell=True)
    time.sleep(2)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_sigint)

    pkt_ctl_log = open("logs/pkt_controller.log", "w")
    ml_detector_log = open("logs/ml_detector.log", "w")

    setup_network_bridge()

    pkt_controller = subprocess.Popen(["./packets_controller_main", "-i", "swp0", "-m", "swp0", "-p", "./xdp_forward_kern.o"], 
                                    cwd="packets_controller", stdout=pkt_ctl_log, stderr=pkt_ctl_log)
    time.sleep(3)

    ml_detector = subprocess.Popen(["python3", "detector_main.py"], cwd="ml_detector", stdout=ml_detector_log, stderr=ml_detector_log)


    print("i.MX DDoS has been started. Press Ctrl C to exit...")
    while not quit_flag:
        time.sleep(1)

    pkt_controller.send_signal(signal.SIGINT)
    ml_detector.send_signal(signal.SIGINT)
    pkt_controller.wait()
    ml_detector.wait()

    pkt_ctl_log.close()
    ml_detector_log.close()

    print("All exit. You can see runtime logs in logs/ folder")