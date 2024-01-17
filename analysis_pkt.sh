#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

#!/bin/bash

echo `date`
PCAP_PATH="/home/root/NetworkingML/$1"
cd /home/root/NetworkingML/deepPacket
python3 tfl_predict.py --ext_delegate /usr/lib/libethosu_delegate.so --model_path ./output_dir/nxp_model-uint8_vela.tflite --pcap $PCAP_PATH --traff_type nxp
cd -

