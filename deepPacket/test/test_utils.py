#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import sys
sys.path.append("..")
import utils
import numpy as np

def test_load_data():
    X, Y = utils.load_data("/home/nxg01813/Code/deepPacket-TF/feature_dir/nxp_dataset_train.npy",
                            "/home/nxg01813/Code/deepPacket-TF/feature_dir/nxp_label_train.npy")
    
    print("X shape: {}".format(X.shape))
    print("Y shape: {}".format(Y.shape))
    print(X)
    print(Y)

if __name__ == '__main__':
    test_load_data()