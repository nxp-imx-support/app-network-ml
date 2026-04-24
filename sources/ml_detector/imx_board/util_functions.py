# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Calculate metrics using numpy

import glob
import numpy as np

class PROTOCOL_NUM:
    PROTOCOL_ICMP = 1
    PROTOCOL_TCP = 6
    PROTOCOL_UDP = 17
    PROTOCOL_IPv4 = 2048

def normalize_num(x, x_min, x_max):
    return (x - x_min) / (x_max - x_min) if (x_max - x_min) != 0 else 0.0

def calculate_metrics(y_true, y_pred):
    """Calculate accuracy, precision, recall and F1 score using numpy"""
    y_true = np.array(y_true).flatten()
    y_pred = np.array(y_pred).flatten()
    
    # Accuracy
    accuracy = np.sum(y_true == y_pred) / len(y_true)
    
    # True Positives, False Positives, False Negatives
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    
    # Precision: TP / (TP + FP)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # Recall: TP / (TP + FN)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return accuracy, precision, recall, f1, tp, fp, fn, tn

def load_dataset(path):
    filename = glob.glob(path)[0]
    import h5py
    dataset = h5py.File(filename, "r")
    set_x_orig = np.array(dataset["set_x"][:])  # features
    set_y_orig = np.array(dataset["set_y"][:])  # labels

    print("X_train shape: {}, type: {}".format(set_x_orig.shape, type(set_x_orig)))
    X_train = set_x_orig.reshape((set_x_orig.shape[0], set_x_orig.shape[1], set_x_orig.shape[2], 1))
    Y_train = set_y_orig#.reshape((1, set_y_orig.shape[0]))

    return X_train, Y_train