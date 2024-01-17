# -*- coding: utf-8 -*-
"""
@File    :   main.py
@Time    :   2023/09/08 11:08:47
@Author  :   Ziheng Xu
@Desc    :   
"""

import os
import tensorflow as tf
import numpy as np
from model import DP_CNN
import argparse
from utils import load_data
from sklearn.metrics import classification_report

traff_type_list = ["traff", "cic2023", "app", "nxp"]
FAST_TRAIN = False

app_params = {
    "c1_output_dim": 200,
    "c1_kernel_size": 4,
    "c1_stride": 3,
    "c2_output_dim": 200,
    "c2_kernel_size": 5,
    "c2_stride": 1,
    "output_dim": 15
}

traff_params = {
    "c1_output_dim": 200,
    "c1_kernel_size": 5,
    "c1_stride": 3,
    "c2_output_dim": 200,
    "c2_kernel_size": 4,
    "c2_stride": 3,
    "output_dim": 5
}

cic2023_params = {
    "c1_output_dim": 200,
    "c1_kernel_size": 5,
    "c1_stride": 3,
    "c2_output_dim": 200,
    "c2_kernel_size": 4,
    "c2_stride": 3,
    "output_dim": 8
}

nxp_params = {
    "c1_output_dim": 200,
    "c1_kernel_size": 5,
    "c1_stride": 3,
    "c2_output_dim": 200,
    "c2_kernel_size": 4,
    "c2_stride": 3,
    "output_dim": 5
}


def train(X_train, Y_train, m_params, batch_size, epochs):
    model = DP_CNN(
                    c1_output_dim=m_params["c1_output_dim"], 
                    c1_kernel_size=m_params["c1_kernel_size"], 
                    c1_stride=m_params["c1_stride"], 
                    c2_output_dim=m_params["c2_output_dim"], 
                    c2_kernel_size=m_params["c2_kernel_size"], 
                    c2_stride=m_params["c2_stride"], 
                    output_dim=m_params["output_dim"]
                )
    
    loss_fn = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True)
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.0003), loss=loss_fn, metrics=['accuracy'])
    
    print("Train set shape, X: {}, Y: {}".format(X_train.shape, Y_train.shape))
    model.fit(X_train, Y_train, batch_size=batch_size, epochs=epochs, shuffle=True)
    print(model.summary())
    
    return model

def test(model, X_test, Y_test):
    print("X_test size: {}, Y_test size: {}".format(X_test.shape, Y_test.shape))
    model.evaluate(X_test, Y_test, verbose=2)
    Y_pred = list()
    for x in X_test:
        input_x = np.expand_dims(x, axis=0)
        tmp = model(input_x)
        tmp = np.squeeze(tmp)
        Y_pred.append(np.argmax(tmp))
    Y_pred = np.array(Y_pred)
    Y_pred = Y_pred.reshape(Y_test.shape[0], 1)
    print(Y_pred.shape)
    print(classification_report(Y_test, Y_pred, digits=4))


def train_main(train_dataset, train_labelset, traff_type, batch_size, epochs, model_path):
    X_train, Y_train = load_data(train_dataset, train_labelset)
    m_params = None
    if traff_type == "app":
        m_params = app_params
    elif traff_type == "traff":
        m_params = traff_params
    elif traff_type == "cic2023":
        m_params = cic2023_params
    elif traff_type == "nxp":
        m_params = nxp_params
    else:
        print("traff_type error.")
        return
    if FAST_TRAIN:
        X_train = X_train[:5000]
        Y_train = Y_train[:5000]
        epochs = 20
    trained_model = train(X_train, Y_train, m_params, batch_size, epochs)
    trained_model.save(model_path)

def test_main(model_path, test_dataset, test_labelset):
    model = tf.keras.models.load_model(model_path)
    X_test, Y_test = load_data(test_dataset, test_labelset)
    test(model, X_test, Y_test)

def main():
    parser = argparse.ArgumentParser(description="For DeepPacket model training.")
    parser.add_argument("--feature_dir", "-f", required=True, help="feature directory after preprocessing.")
    parser.add_argument("--traff_type", "-t", required=True, help="model type: app|traff|cic2023")
    parser.add_argument("--output_dir", "-o", required=True, help="model output path")
    parser.add_argument("--batch_size", "-b", default=128, help="batch size")
    parser.add_argument("--epochs", "-e", default=20, help="training epochs")
    parser.add_argument("--mode", "-m", required=True, help="train|test")
    args = parser.parse_args()

    traff_type = args.traff_type
    feature_dir = args.feature_dir
    batch_size = int(args.batch_size)
    epochs = int(args.epochs)
    output_dir = args.output_dir
    mode = args.mode

    train_dataset = None
    test_dataset = None
    
    if traff_type in traff_type_list:
        train_dataset = os.path.join(feature_dir, "{}_dataset_train.npy".format(traff_type))
        train_labelset = os.path.join(feature_dir, "{}_label_train.npy".format(traff_type))
        test_dataset = os.path.join(feature_dir, "{}_dataset_test.npy".format(traff_type))
        test_labelset = os.path.join(feature_dir, "{}_label_test.npy".format(traff_type))
    
    if train_dataset is None or test_dataset is None:
        print("[ERROR] --traff_type is wrong")
        exit(0)
    if not os.path.exists(train_dataset) or not os.path.exists(test_dataset):
        print("[ERROR] dataset file not exist.")
        exit(0)
    if not os.path.exists(output_dir):
        print("[ERROR] output directory is not exist")
        exit(0)
    model_path = os.path.join(output_dir, "{}_model.h5".format(traff_type))

    if mode == "train":
        train_main(train_dataset, train_labelset, traff_type, batch_size, epochs, model_path)
    else:
        test_main(model_path, test_dataset, test_labelset)


if __name__ == '__main__':
    main()
    # test_main()
