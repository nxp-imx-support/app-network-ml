# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
# DeepPacket model

import tensorflow as tf
from keras import Model
from keras import Sequential
from keras.layers import Conv1D, Dense, MaxPooling1D, Flatten, Dropout, BatchNormalization
from keras.layers import Dropout, ReLU
from config import MAX_LENGTH, WIN_SIZE


def DP_CNN(
            c1_output_dim,
            c1_kernel_size,
            c1_stride,
            c2_output_dim,
            c2_kernel_size,
            c2_stride,
            output_dim,
            dropout=0.3
            ):
    
    model = Sequential(name="DeepPacket_CNN")
    model.add(Conv1D(filters=c1_output_dim, kernel_size=c1_kernel_size, strides=c1_stride, activation='relu', input_shape=(MAX_LENGTH, WIN_SIZE)))
    model.add(Conv1D(filters=c2_output_dim, kernel_size=c2_kernel_size, strides=c2_stride, activation='relu'))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Flatten())
    denses = [600, 150, 50]
    for dense in denses:
        model.add(Dense(dense, activation="relu"))
        model.add(Dropout(dropout))
    model.add(Dense(output_dim))

    # print(model.summary())
    return model
    

if __name__ == '__main__':
    model = DP_CNN(c1_output_dim=200, c1_kernel_size=5, c1_stride=3, 
                   c2_output_dim=200, c2_kernel_size=4, c2_stride=3, output_dim=12)

    loss_object = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True)
    optimizer = tf.keras.optimizers.Adam()

    with tf.GradientTape() as tape:
        x_shape = (120, 1500, 1)
        x = tf.random.normal(x_shape)
        pred = model(x, training=True)
        print(pred.shape)
        print(type(pred))


