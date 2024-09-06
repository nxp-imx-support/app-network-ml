# Detect running platform, i.MX93 or i.MX95
# Configure DPDK on i.MX95

import os
import subprocess
import signal
import time
import shutil

support_platforms = ["imx95evk", "imx93evk"]

USE_NPU = True

L2CAPFWD_APP = "./l2capfwd"
MODEL_APP_DIR = "./model"
MODEL_APP = "model_inference_main.py"
MODEL_NAME = "LUCID-ddos-CIC2019-quant-int8.tflite"
MODEL_NAME_NPU = "LUCID-ddos-CIC2019-quant-int8_vela.tflite"
WEBUI_APP_DIR = "./webui"
WEBUI_APP = "web_main.py"

quit_flag = False

def get_host_ip():
    sh_ret = subprocess.run("ip address | grep 'inet '", shell=True, capture_output=True, text=True)
    for item in sh_ret.stdout.splitlines():
        inet_addr = item.strip().split(" ")[1]
        inet_addr = inet_addr.split("/")[0]
        if inet_addr[:3] == "127" or inet_addr[:3] == "169":
            continue
        return inet_addr

def handle_signal(signum, frame):
    global quit_flag
    print("Recv quit signal, exit...")
    quit_flag = True
    return

def detect_running_platform():
    ret = subprocess.run(["hostname"], capture_output=True, text=True)
    hostname = ""
    if ret.returncode == 0:
        hostname = ret.stdout
    return hostname.strip()

def config_imx95_dpdk():
    sh_ret = subprocess.run("lsmod | grep kpage_ncache", shell=True, encoding="utf-8", capture_output=True, text=True)
    if sh_ret.stdout.strip() == '':
        print("Loading kpage_ncacke.ko.")
        sh_ret = subprocess.run(["modprobe", "kpage_ncache"])
        if sh_ret.returncode != 0:
            print("Error when modprobe kpage_ncache")
            return -1
    sh_ret = subprocess.run(["dpdk-devbind.py", "-s"], capture_output=True, text=True)
    if sh_ret.returncode != 0:
        print("Error when dpdk-devbind.py -s")
        return -1

    # Get PF PCI address
    pf_pci_addrs = []
    for row in sh_ret.stdout.splitlines():
        if "drv=fsl_enetc4" in row:
            pf_pci_addrs.append(row.split(" ")[0])
    print("PF PCI addresses are: {}".format(pf_pci_addrs))

    # Create VF for each PF
    for pf_addr in pf_pci_addrs:
        subprocess.run("echo 1 > /sys/bus/pci/devices/{}/sriov_numvfs".format(pf_addr), shell=True)
    
    sh_ret = subprocess.run(["dpdk-devbind.py", "-s"], capture_output=True, text=True)
    if sh_ret.returncode != 0:
        print("Error when dpdk-devbind.py -s")
        return -1
    # Get VF PCI address and device name
    vf_pci_addrs = []
    vf_dev_name = []
    dpdk_configure_flag = False
    for row in sh_ret.stdout.splitlines():
        if "drv=fsl_enetc_vf" in row:
            tmp_list = row.split(" ")
            vf_pci_addrs.append(tmp_list[0])
            vf_dev_name.append(tmp_list[3][3:])
        if "drv=uio_pci_generic" in row:
            dpdk_configure_flag = True
    if dpdk_configure_flag:
        print("DPDK VFs have been configured. Skip.")
        return 0
    print("VF PCI addresses are: {}".format(vf_pci_addrs))
    print("VF devices are: {}".format(vf_dev_name))
    # down eth device, then bind dpdk dev
    cmd = """
        ip link set {} down
        ip link set {} down
        dpdk-devbind.py -b uio_pci_generic {}
        dpdk-devbind.py -b uio_pci_generic {}
        ip link set eth0 vf 0 trust on
        ip link set eth1 vf 0 trust on
        """.format(vf_dev_name[0], vf_dev_name[1], vf_pci_addrs[0], vf_pci_addrs[1])
    sh_ret = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    if sh_ret.returncode == 0:
        print("Configure finished.")
    return 0

def config_imx93_dpdk():
    sh_ret = subprocess.run("lsmod | grep kpage_ncache", shell=True, encoding="utf-8", capture_output=True, text=True)
    if sh_ret.stdout.strip() == '':
        print("Loading kpage_ncacke.ko.")
        sh_ret = subprocess.run(["modprobe", "kpage_ncache"])
        if sh_ret.returncode != 0:
            print("Error when modprobe kpage_ncache")
            return -1
    cmd = """
        mkdir -p /dev/hugepages
        mount -t hugetlbfs hugetlbfs /dev/hugepages
        echo 448 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
        """
    sh_ret = subprocess.run(["bash", "-c", cmd])
    if sh_ret.returncode != 0:
        print("Error when configure hugepages.")
        return -1
    return 0

def build_model_imx93():
    sh_ret = None
    original_dir = os.getcwd()
    if not os.path.exists("./model/LUCID-ddos-CIC2019-quant-int8_vela.tflite"):
        print("Start vela building.")
        os.chdir("model")
        sh_ret = subprocess.run("vela ./LUCID-ddos-CIC2019-quant-int8.tflite", shell=True, capture_output=True)
        shutil.move("./output/LUCID-ddos-CIC2019-quant-int8_vela.tflite", ".")
        shutil.rmtree("output")
        os.chdir(original_dir)
        print("End vela building.")
    return 0

def execute_demo_loop(hostname):
    global quit_flag
    original_dir = os.getcwd()
    # Start up l2capfwd
    if not os.access(L2CAPFWD_APP, os.X_OK):
        os.chmod(L2CAPFWD_APP, 0o770)
    print("Start l2capfwd process")
    args = "-c 0x3 -n 2 --vdev 'net_enetqos' --vdev 'net_enetfec' -- -p 0x3 -P -T 5 --no-mac-updating > ./debug.log 2>&1"
    cmd_str = "{} {}".format(L2CAPFWD_APP, args)
    l2capfwd_process = subprocess.Popen(cmd_str, shell=True)
    print("l2capfwd pid: {}".format(l2capfwd_process.pid))

    # Start up AI model
    os.chdir(MODEL_APP_DIR)
    print("Start AI inference process")
    cmd_str = ""
    if USE_NPU and hostname == "imx93evk":
        cmd_str = "python3 {} --model {} -e /usr/lib/libethosu_delegate.so > ./debug.log 2>&1".format(MODEL_APP, MODEL_NAME_NPU)
    else:
        cmd_str = "python3 {} --model {} > ./debug.log 2>&1".format(MODEL_APP, MODEL_NAME)
    infer_process = subprocess.Popen(cmd_str, shell=True)
    print("inference pid: {}".format(infer_process.pid))

    # Start up WebUI
    os.chdir(os.path.join(original_dir, WEBUI_APP_DIR))
    cmd_str = "python3 {} > debug.log 2>&1".format(WEBUI_APP)
    webui_process = subprocess.Popen(cmd_str, shell=True)
    print("webui pid: {}".format(webui_process.pid))
    print("***** WebUI listen on {}:5000 *****".format(get_host_ip()))
    print("Ctrl C to exit")

    os.chdir(original_dir)   
    # Wait for exit signal
    while quit_flag == False:
        time.sleep(1)
    l2capfwd_process.terminate()
    infer_process.terminate()
    webui_process.terminate()

    print("Waiting subprocess exit...")
    l2capfwd_process.wait()
    print("l2capfwd exit.")
    infer_process.wait()
    print("inference exit.")
    webui_process.wait()
    print("webui exit.")
    print("All exit.")
    return

def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    host_name = detect_running_platform()
    if host_name not in support_platforms:
        print("[INFO] The current platform is not supported. Current platform: {}.".format(host_name))
        return
    config_status = -1
    # i.MX95
    if host_name == "imx95evk":
        config_status = config_imx95_dpdk()

    # i.MX93
    if host_name == "imx93evk":
        config_status = config_imx93_dpdk()
        if config_status != 0:
            return
        if USE_NPU:
            config_status = build_model_imx93()

    # Execute demo
    if config_status == 0:
        execute_demo_loop(host_name)
    return

if __name__ == '__main__':
    main()
