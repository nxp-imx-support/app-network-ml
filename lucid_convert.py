# -*- coding: utf-8 -*-
# @Time : 2020/3/21
# @File :convert2tflite.py
# @Software: PyCharm


import numpy as np
import tensorflow as tf
import glob
import h5py

  # defined by tf.keras


# # path of the directory where you want to save your model
# frozen_out_path = 'model'  # model path
# # name of the .pb file
# frozen_graph_filename = "facemask"  #model name


keras_model = "output/10t-10n-DOS2019-LUCID.h5"
out_tflite = 'output/10t-10n-DOS2019-LUCID-quant-uint8.tflite'

dataset_folder = "sample-dataset"

def load_dataset(path):
    filename = glob.glob(path)[0]
    dataset = h5py.File(filename, "r")
    set_x_orig = np.array(dataset["set_x"][:])  # features
    set_y_orig = np.array(dataset["set_y"][:])  # labels

    X_train = np.reshape(set_x_orig, (set_x_orig.shape[0], set_x_orig.shape[1], set_x_orig.shape[2], 1))
    Y_train = set_y_orig#.reshape((1, set_y_orig.shape[0]))

    return X_train, Y_train


def get_representative_dataset_gen():
    X_train, _ = load_dataset(dataset_folder + "/*" + '-train.hdf5')
    print(X_train.shape)
    for x in X_train:
        input_data = np.expand_dims(x, axis=0)
        input_data = input_data.astype(np.float32)
        yield [input_data]
    #     input_data = np.expand_dims(img, axis=0)
    #     #img = img_raw_rgb - 127
    #     yield [input_data]

def keras2tflite( model ):

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


# def main(_):

    # #keras to savemodel (.pb)
model = tf.keras.models.load_model(keras_model, custom_objects={'tf': tf}, compile=False)
model.summary()
keras2tflite(model)

# get_representative_dataset_gen()
