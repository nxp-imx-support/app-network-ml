# -*- coding: utf-8 -*-
# @Time : 2020/3/21
# @File :convert2tflite.py
# @Software: PyCharm


import numpy as np
import tensorflow as tf
import glob
import h5py
import sys

dataset_path = ""
out_tflite = ""
keras_model = ""

def load_dataset(path):
    filename = glob.glob(path)[0]
    dataset = h5py.File(filename, "r")
    set_x_orig = np.array(dataset["set_x"][:])  # features
    set_y_orig = np.array(dataset["set_y"][:])  # labels

    X_train = np.reshape(set_x_orig, (set_x_orig.shape[0], set_x_orig.shape[1], set_x_orig.shape[2], 1))
    Y_train = set_y_orig#.reshape((1, set_y_orig.shape[0]))

    return X_train, Y_train


def get_representative_dataset_gen():
    X_train, _ = load_dataset(dataset_path)
    print(X_train.shape)
    for x in X_train:
        input_data = np.expand_dims(x, axis=0)
        input_data = input_data.astype(np.float32)
        yield [input_data]


def keras2tflite(model):

    converter = tf.lite.TFLiteConverter.from_keras_model(model)

    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.representative_dataset = get_representative_dataset_gen

    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]

    # converter.inference_input_type = tf.int8
    # converter.inference_output_type = tf.int8

    tflite_model = converter.convert()
    open(out_tflite, "wb").write(tflite_model)
    print("successfully convert to tflite done")
    print("save model at: {}".format(out_tflite))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python3 {} <keras_model_path> <output_model_path> <representative_dataset_path>".format(__file__))
        exit(0)
    
    keras_model = sys.argv[1]
    out_tflite = sys.argv[2]
    dataset_path = sys.argv[3]

    model = tf.keras.models.load_model(keras_model, custom_objects={'tf': tf}, compile=False)
    model.summary()
    keras2tflite(model)
