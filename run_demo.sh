#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

#!/bin/bash

QUIT_FLAG=0

source ./config

setup_env() {
    pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

    if [ ! -d "./deepPacket/feature_dir" ]; then
        mkdir ./deepPacket/feature_dir
    fi

    if [ ! -d "./deepPacket/output_dir" ]; then
        mkdir ./deepPacket/output_dir
    fi

    if [ ! -d "pcaps" ]; then
        mkdir pcaps
    fi
}

detect_running_platform() {
    hostname | tr -d '\n'
}

check_br_veth() {
    if ip link show | grep -q br0; then
        echo "br0 and veth have been configured."
        return 1
    fi
    return 0
}

config_br_veth() {
    ip link add name br0 type bridge
    ip link set br0 up

    ip link add veth0 type veth peer name veth1
    # ip addr add $1 dev veth0
    ip link set veth0 up
    ip link set veth1 up

    ip link set eth0 down
    ip link set eth1 down
    ip link set eth0 up
    ip link set eth1 up

    ip link set dev eth0 master br0
    ip link set dev eth1 master br0
    ip link set dev veth1 master br0

    # wait for DHCP
    sleep 15s
    route del default gw 0.0.0.0
}

clean_br_veth() {
    ip link set br0 down
    ip link set veth0 down
    ip link set veth1 down
    ip link del br0
    ip link del veth0
    echo "clean br0 and veth."
}

imx93_model_build() {
    echo "vela"
    if [ ! -d vela_output ]; then
        mkdir vela_output
    fi
    if [ ${USE_NPU} == 1 ]; then
        ln -sf /usr/lib/libethosu_delegate.so ${DELEGATE_PATH_LINK}
        vela --output-dir ./vela_output ${MODEL_PATH}
        ln -sf ./vela_output/${MODEL_PATH%.tflite}_vela.tflite ${MODEL_PATH_LINK}
    else
        ln -sf ${MODEL_PATH} ${MODEL_PATH_LINK}
    fi
    return 0
}

imx95_model_build() {
    echo "neutron-convert"
    if [ ${USE_NPU} == 1 ]; then
        ln -sf /usr/lib/libneutron_delegate.so ${DELEGATE_PATH_LINK}
        ln -sf ${MODEL_PATH} ${MODEL_PATH_LINK}
    else
        ln -sf ${MODEL_PATH} ${MODEL_PATH_LINK}
    fi
}

handle_exit_signal() {
    echo "Recv quit signal, exit..."
    QUIT_FLAG=1
}


run_loop() {
    trap handle_exit_signal SIGINT SIGTERM

    if [ -n "$(ls -A pcaps)" ]; then
        rm pcaps/*
    fi
    rm -f deepPacket/output_dir/*.pickle

    cd WebSys
    python3 main.py &
    webui_pid=$!
    cd -

    tcpdump -i eth0 -G 7 -w pcaps/%Y_%m_%d-%H_%M_%S.pcap -z "./analysis_pkt.sh" not ip6 and not icmp and not port 5000 and not port 1900 &
    tcpdump_pid=$!

    # Check if both processes are running
    while (( ${QUIT_FLAG} == 0));do
        if ! kill -0 ${webui_pid} 2>/dev/null; then
            QUIT_FLAG=1
            break
        fi
        if ! kill -0 ${tcpdump_pid} 2>/dev/null; then
            QUIT_FLAG=1
            break
        fi
        sleep 1
    done

    # Cleanup
    kill -TERM ${webui_pid} 2>/dev/null
    wait ${webui_pid}
    echo "webui exit."
    kill -TERM ${tcpdump_pid} 2>/dev/null
    wait ${tcpdump_pid}
    echo "tcpdump exit."
}

start_demo() {
    local host_name=$(detect_running_platform)
    # only for debug, need to remove when release!!
    case ${host_name} in
        "imx95evk")
            echo "running on imx95"
            imx95_model_build
            ;;
        "imx93evk")
            echo "running on imx93"
            imx93_model_build
            ;;
        *)
            echo "[INFO] Current platform is not supported. $host_name"
    esac

    if check_br_veth; then
        config_br_veth
    fi

    run_loop
}

show_help() {
    echo "$0 setup|start|clean"
}

# check arguments number
if [ $# -eq 1 ]; then
    case "$1" in
        "clean")
            clean_br_veth
            ;;
        "start")
            start_demo
            ;;
        "setup")
            setup_env
            ;;
        *)
            echo "Invalid paramenter $1"
            show_help
    esac
else
    show_help
fi
