# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# 
# Convert & Quantification


import numpy as np
import tensorflow as tf
import argparse
import os
from utils import load_data

  # defined by tf.keras


# # path of the directory where you want to save your model
# frozen_out_path = 'model'  # model path
# # name of the .pb file
# frozen_graph_filename = "facemask"  #model name


dataset = None

def get_representative_dataset_gen():
    print("[DEBUG] dataset: {}".format(dataset))
    X_train, _ = load_data(dataset, None)
    X_train = X_train[:1000]
    print(X_train.shape)
    for x in X_train:
        input_data = np.expand_dims(x, axis=0)
        input_data = input_data.astype(np.float32)
        yield [input_data]
    #     input_data = np.expand_dims(img, axis=0)
    #     #img = img_raw_rgb - 127
    #     yield [input_data]

def keras2tflite(model, out_tflite):

    converter = tf.lite.TFLiteConverter.from_keras_model(model)

    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.representative_dataset = get_representative_dataset_gen

    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]

    converter.inference_input_type = tf.uint8
    converter.inference_output_type = tf.uint8


    tflite_model = converter.convert()
    open(out_tflite, "wb").write(tflite_model)
    print("successfully convert to tflite done")
    print("save model at: {}".format(out_tflite))
    # tflite_model.summary()

def main():
    global dataset

    parser = argparse.ArgumentParser(description="Convert and quantify model")
    parser.add_argument("--model_path", required=True, help="model path to be converted.")
    parser.add_argument("--dataset", required=True, help="representative dataset path")
    args = parser.parse_args()

    model_path = args.model_path
    dataset = args.dataset
    out_tflite = os.path.splitext(model_path)[0] + "-uint8.tflite"

    model = tf.keras.models.load_model(model_path, compile=False)
    print(model.summary())
    keras2tflite(model, out_tflite)

if __name__ == '__main__':
    main()