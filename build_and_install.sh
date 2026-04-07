#!/bin/bash
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

set -e

TARGET_PATH="./board_deploy"

echo "Build and create deployment package"

rm -rf ${TARGET_PATH}

if [ -z "${TOOLCHAIN_PATH}" ]; then
    echo "Error: TOOLCHAIN_PATH is not set"
    exit 1
fi

echo "Build packets controller..."
source ${TOOLCHAIN_PATH}
make -C sources/packets_controller clean
make -C sources/packets_controller all
echo "Build packets controller completed"

echo "Installing..."
install -d ${TARGET_PATH}/packets_controller
install -d ${TARGET_PATH}/ml_detector/model

install -m 544 sources/tools/setup_network_bridge.sh ${TARGET_PATH}

install -m 544 sources/packets_controller/build/packets_controller_main ${TARGET_PATH}/packets_controller/packets_controller_main
install -m 544 sources/packets_controller/xdp/xdp_forward_kern.o ${TARGET_PATH}/packets_controller/xdp_forward_kern.o
install -m 644 sources/ml_detector/imx_board/*.py ${TARGET_PATH}/ml_detector
install -m 644 sources/ml_detector/imx_board/detector.toml ${TARGET_PATH}/ml_detector
install -m 644 output/LUCID-ddos-CIC2019-quant-int8.tflite ${TARGET_PATH}/ml_detector/model/

echo "Done"
