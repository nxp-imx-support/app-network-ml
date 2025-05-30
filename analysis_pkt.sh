#!/bin/bash
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Do not execute this script manually, it should be called by tcpdump.

source ./config
echo `date`

cd deepPacket
if [ ${USE_NPU} == 1 ]; then
    python3 tfl_predict.py --ext_delegate ${DELEGATE_PATH_LINK} --model_path ${MODEL_PATH_LINK} --pcap ${ROOT_PATH}/$1 --traff_type nxp
else
    python3 tfl_predict.py --model_path ${MODEL_PATH_LINK} --pcap ${ROOT_PATH}/$1 --traff_type nxp
fi
cd -

