#!/bin/bash
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

SOCKET_PATH="/tmp/imx-ddb-socket"
XDP_PROG="./xdp_forward_kern.o"
XDP_CTRL="./xdp_controller"
MODEL_DIR="./model"
WEBUI_DIR="./webui"
QUIT_FLAG=0
declare -A PIDS

detect_platform() {
    hostname | tr -d '\n'
}

get_interface() {
    local platform=$1
    case $platform in
        imx93evk) echo "eth0" ;;
        imx95evk) echo "eth0" ;;
        imx943-orangebox) echo "swp0" ;;
        *) echo "eth0" ;;
    esac
}

get_npu_delegate() {
    local platform=$1
    case $platform in
        imx93evk) echo "/usr/lib/libethosu_delegate.so" ;;
        imx95evk|imx943-orangebox) echo "/usr/lib/libneutron_delegate.so" ;;
        *) echo "" ;;
    esac
}

handle_signal() {
    echo "Shutting down..."
    QUIT_FLAG=1
}

cleanup() {
    for proc in "${!PIDS[@]}"; do
        kill -TERM ${PIDS[$proc]} 2>/dev/null
        echo "$proc stopped"
    done
    rm -f $SOCKET_PATH
}

main() {
    trap handle_signal SIGINT SIGTERM
    trap cleanup EXIT

    local platform=$(detect_platform)
    local iface=$(get_interface $platform)
    local npu_delegate=$(get_npu_delegate $platform)

    echo "Platform: $platform"
    echo "Interface: $iface"

    rm -f $SOCKET_PATH

    echo "Starting XDP controller..."
    $XDP_CTRL -i $iface -p $XDP_PROG -s $SOCKET_PATH &
    PIDS["xdp"]=$!

    sleep 2

    echo "Starting inference..."
    cd $MODEL_DIR
    python3 model_inference_main_refactored.py \
        --model_id lucid_cnn \
        -m LUCID-ddos-CIC2019-quant-int8.tflite \
        -e $npu_delegate \
        -s $SOCKET_PATH &
    PIDS["inference"]=$!
    cd ..

    sleep 2

    echo "Starting WebUI..."
    cd $WEBUI_DIR
    python3 web_main.py &
    PIDS["webui"]=$!
    cd ..

    echo "System started. WebUI: http://$(hostname -I | awk '{print $1}'):5000"
    echo "Press Ctrl+C to stop"

    while (( QUIT_FLAG == 0 )); do
        sleep 1
    done
}

main "$@"
