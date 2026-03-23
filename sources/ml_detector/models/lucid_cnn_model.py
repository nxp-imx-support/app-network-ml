# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

import tensorflow as tf
import numpy as np
from .base_model import BaseModel
from util_functions import *
from keras.models import Sequential
from keras.layers import Input, Conv2D, GlobalMaxPooling2D, Flatten, Dense
from keras.optimizers import Adam

class LucidCNNModel(BaseModel):
    """LUCID CNN model for DDoS detection (PC side - training/conversion)"""

    def __init__(self):
        super().__init__("LUCID-CNN")
        self.model = None

    def build(self, input_shape, kernel_col=11, kernels=64, kernel_rows=3,
              learning_rate=0.0001, regularization=None, dropout=0.2):

        self.input_shape = input_shape
        model = Sequential(name=self.model_name)

        model.add(Input(shape=input_shape))
        model.add(Conv2D(kernels, (kernel_rows, kernel_col), strides=(1, 1),
                        kernel_regularizer=regularization, activation="relu", name='conv0'))
        model.add(GlobalMaxPooling2D())
        model.add(Flatten())
        model.add(Dense(1, activation=tf.keras.activations.sigmoid, name='fc1'))

        optimizer = Adam(learning_rate=learning_rate)
        model.compile(loss='binary_crossentropy', optimizer=optimizer, metrics=['accuracy'])

        self.model = model
        return model

    def train(self, X_train, Y_train, X_val, Y_val, epochs, batch_size=1024):
        if self.model is None:
            raise ValueError("Model not built. Call build() first.")

        self.model.fit(X_train, Y_train, epochs=epochs,
                      validation_data=(X_val, Y_val), batch_size=batch_size)
        return self.model

    def save(self, output_path):
        if self.model is None:
            raise ValueError("No model to save")
        self.model.save(output_path + ".keras")

    def convert_to_tflite(self, model_path, output_path, dataset_path):
        X_train, _ = load_dataset(dataset_path)

        def representative_dataset_gen():
            for x in X_train:
                input_data = np.expand_dims(x, axis=0).astype(np.float32)
                yield [input_data]

        model_keras = tf.keras.models.load_model(model_path)
        converter = tf.lite.TFLiteConverter.from_keras_model(model_keras)
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.representative_dataset = representative_dataset_gen
        converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        converter.inference_input_type = tf.int8
        converter.inference_output_type = tf.int8

        tflite_model = converter.convert()
        with open(output_path, "wb") as f:
            f.write(tflite_model)
