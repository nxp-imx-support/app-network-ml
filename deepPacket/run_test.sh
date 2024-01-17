#! /bin/bash
set -v on

python preprocess.py --traff_type nxp --feature_dir ./feature_dir --pcap_dir /opt/Dataset/NXP-Traff
python main.py --traff_type nxp --feature_dir ./feature_dir/ --output_dir ./output_dir/ --mode train
python main.py --traff_type nxp --feature_dir ./feature_dir/ --output_dir ./output_dir/ --mode test
