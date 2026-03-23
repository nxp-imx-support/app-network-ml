# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import sys
from sklearn.utils import shuffle

# Add parent directory to path
# sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from model_pool import ModelPool
from models.lucid_cnn_model import LucidCNNModel
from models.simple_dnn_model import SimpleDNNModel
from util_functions import load_dataset, SEED

OUTPUT_FOLDER = "../../output/"
model_pool = ModelPool()

def train_model(model_id, dataset_folder, epochs):
    """Train a model from the pool"""
    model = model_pool.get_model(model_id)
    if model is None:
        raise ValueError(f"Model {model_id} not registered")

    X_train, Y_train = load_dataset(dataset_folder + '/dataset_train.hdf5')
    X_val, Y_val = load_dataset(dataset_folder + '/dataset_val.hdf5')
    X_test, Y_test = load_dataset(dataset_folder + '/dataset_test.hdf5')

    X_train, Y_train = shuffle(X_train, Y_train, random_state=SEED)
    X_val, Y_val = shuffle(X_val, Y_val, random_state=SEED)

    print(f"Training {model.model_name}")
    print(f"X_train: {X_train.shape}, Y_train: {Y_train.shape}")

    model.build(input_shape=X_train.shape[1:], kernel_col=X_train.shape[2])
    model.train(X_train, Y_train, X_val, Y_val, epochs)

    print("Evaluating on test set")
    model.model.evaluate(X_test, Y_test)

    output_path = os.path.join(OUTPUT_FOLDER, f"{model.model_name}-ddos-CIC2019")
    model.save(output_path)
    print(f"Model saved to {output_path}.keras")

def convert_model(model_id, keras_path, tflite_path, dataset_path):
    """Convert a model to TFLite"""
    model = model_pool.get_model(model_id)
    if model is None:
        raise ValueError(f"Model {model_id} not registered")

    model.convert_to_tflite(keras_path, tflite_path, dataset_path)
    print(f"Converted to {tflite_path}")

def main():
    # Register models
    model_pool.register("lucid_cnn", LucidCNNModel())
    model_pool.register("simple_dnn", SimpleDNNModel())
    model_pool.set_active("lucid_cnn")

    parser = argparse.ArgumentParser(description='DDoS detection model training and conversion')
    parser.add_argument('-m', '--model', default='lucid_cnn', help='Model ID to use')
    parser.add_argument('-t', '--train', type=str, help='Dataset folder for training')
    parser.add_argument('-e', '--epochs', default=100, type=int, help='Training epochs')
    parser.add_argument('-c', '--convert', nargs=3, metavar=('KERAS', 'TFLITE', 'DATASET'),
                       help='Convert model: keras_path tflite_path dataset_path')
    parser.add_argument('--list', action='store_true', help='List available models')

    args = parser.parse_args()

    if not os.path.isdir(OUTPUT_FOLDER):
        os.mkdir(OUTPUT_FOLDER)

    if args.list:
        print("Available models:", model_pool.list_models())
        return

    if args.train:
        train_model(args.model, args.train, args.epochs)
    elif args.convert:
        convert_model(args.model, args.convert[0], args.convert[1], args.convert[2])
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
