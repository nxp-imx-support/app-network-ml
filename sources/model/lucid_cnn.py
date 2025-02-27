# Copyright (c) 2022 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Example commands
# Training: python3 lucid_cnn.py --train ../../sample-dataset/  --epochs 100 -cv 5
# Predict: python3 lucid_cnn.py --predict ../..sample-dataset/ --model ../../output/LUCID-ddos-CIC2019.keras

import tensorflow as tf
import numpy as np
import random as rn
import os
import sys
import csv
import pprint
import time
import argparse
from util_functions import *
# from lucid_dataset_parser import *
# Seed Random Numbers
os.environ['PYTHONHASHSEED']=str(SEED)
np.random.seed(SEED)
rn.seed(SEED)
config = tf.compat.v1.ConfigProto(inter_op_parallelism_threads=1)

from tensorflow.keras.optimizers import Adam,SGD
from tensorflow.keras.layers import Input, Dense, Activation, Flatten, Conv2D
from tensorflow.keras.layers import Dropout, GlobalMaxPooling2D, MaxPooling2D
from tensorflow.keras.models import Model, Sequential, load_model, save_model
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix
from sklearn.utils import shuffle
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
# from tensorflow.keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV

import tensorflow.keras.backend as K
tf.random.set_seed(SEED)
K.set_image_data_format('channels_last')
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
#config.log_device_placement = True  # to log device placement (on which device the operation ran)

OUTPUT_FOLDER = "../../output/"

VAL_HEADER = ['Model', 'Samples', 'Accuracy', 'F1Score', 'Hyper-parameters','Validation Set']
PREDICT_HEADER = ['Model', 'Time', 'Packets', 'Samples', 'DDOS%', 'Accuracy', 'F1Score', 'TPR', 'FPR','TNR', 'FNR', 'Source']

# hyperparameters
DEFAULT_EPOCHS = 100

def Conv2DModel(model_name, input_shape, kernel_col, kernels=64, kernel_rows=3, 
                learning_rate=0.0001, regularization=None, dropout=0.2):
    
    model = Sequential(name=model_name)
    regularizer = regularization

    model.add(Input(shape=input_shape))
    model.add(Conv2D(kernels, (kernel_rows,kernel_col), strides=(1, 1), 
                     kernel_regularizer=regularizer, activation="relu", name='conv0'))
    model.add(GlobalMaxPooling2D())
    model.add(Flatten())
    model.add(Dense(1, activation=tf.keras.activations.sigmoid, name='fc1'))

    print(model.summary())
    compileModel(model, learning_rate)
    return model

def compileModel(model,lr):
    # optimizer = SGD(learning_rate=lr, momentum=0.0, decay=0.0, nesterov=False)
    optimizer = Adam(learning_rate=lr)
    model.compile(loss='binary_crossentropy', optimizer=optimizer, metrics=['accuracy'])  # here we specify the loss function

def main(argv):
    help_string = 'Usage: python3 lucid_cnn.py --train <dataset_folder> -e <epocs>'

    parser = argparse.ArgumentParser(
        description='DDoS attacks detection with convolutional neural networks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-t', '--train', type=str,
                        help='Start the training process')

    parser.add_argument('-e', '--epochs', default=DEFAULT_EPOCHS, type=int,
                        help='Training iterations')

    parser.add_argument('-cv', '--cross_validation', default=0, type=int,
                        help='Number of folds for cross-validation (default 0)')

    parser.add_argument('-a', '--attack_net', default=None, type=str,
                        help='Subnet of the attacker (used to compute the detection accuracy)')

    parser.add_argument('-v', '--victim_net', default=None, type=str,
                        help='Subnet of the victim (used to compute the detection accuracy)')

    parser.add_argument('-p', '--predict', nargs='?', type=str,
                        help='Perform a prediction on pre-preprocessed data')

    parser.add_argument('-i', '--iterations', default=1, type=int,
                        help='Predict iterations')

    parser.add_argument('-m', '--model', type=str,
                        help='File containing the model')

    parser.add_argument('-y', '--dataset_type', default=None, type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019, SYN2020')

    args = parser.parse_args()

    if os.path.isdir(OUTPUT_FOLDER) == False:
        os.mkdir(OUTPUT_FOLDER)

    if args.train is not None:
        dataset_folder = args.train
        X_train, Y_train = load_dataset(dataset_folder + '/dataset_train.hdf5')
        X_val, Y_val = load_dataset(dataset_folder + '/dataset_val.hdf5')
        X_test, Y_test = load_dataset(dataset_folder + '/dataset_test.hdf5')

        X_train, Y_train = shuffle(X_train, Y_train, random_state=SEED)
        X_val, Y_val = shuffle(X_val, Y_val, random_state=SEED)

        print ("\nCurrent dataset folder: ", dataset_folder)
        print("X_train shape: {}, Y_train shape: {}, X_val shape: {}, Y_val shape: {}".format(
            X_train.shape, Y_train.shape, X_val.shape, Y_val.shape))

        model_name = "LUCID-ddos-CIC2019"

        model = Conv2DModel(model_name, input_shape=X_train.shape[1:], kernel_col=X_train.shape[2])

        model.fit(X_train, Y_train, epochs=args.epochs, validation_data=(X_val, Y_val), batch_size=1024)
        print("Evaluate test dataset")
        model.evaluate(X_test, Y_test)

        model_save_path = os.path.join(OUTPUT_FOLDER, model_name)
        model.save(model_save_path)

        # another save method for eval Keras model
        model.save(model_save_path + ".keras")

        print("Best model path: ", model_save_path)

    if args.predict is not None:
        predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
        predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
        predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
        predict_writer.writeheader()
        predict_file.flush()

        iterations = args.iterations

        dataset_folder = args.predict

        if args.model is not None:
            model_list = [args.model]
        else:
            model_list = glob.glob(args.predict + "/*.h5")

        for model_path in model_list:
            model = load_model(model_path)

            X, Y = load_dataset(dataset_folder + "/dataset_test.hdf5")
            # [packets] = count_packets_in_dataset([X])

            Y_pred = None
            Y_true = Y
            avg_time = 0
            for iteration in range(iterations):
                pt0 = time.time()
                Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5)
                pt1 = time.time()
                avg_time += pt1 - pt0

            avg_time = avg_time / iterations

            report_results(np.squeeze(Y_true), Y_pred, model_path, dataset_folder, avg_time,predict_writer)
            accuracy = accuracy_score(y_true=Y_true, y_pred=Y_pred)
            print("accuracy: {}".format(accuracy))
            predict_file.flush()

        predict_file.close()


def report_results(Y_true, Y_pred, model_name, data_source, prediction_time, writer):
    ddos_rate = '{:04.3f}'.format(sum(Y_pred) / Y_pred.shape[0])

    if Y_true is not None and len(Y_true.shape) > 0:  # if we have the labels, we can compute the classification accuracy
        Y_true = Y_true.reshape((Y_true.shape[0], 1))
        accuracy = accuracy_score(Y_true, Y_pred)

        f1 = f1_score(Y_true, Y_pred)
        tn, fp, fn, tp = confusion_matrix(Y_true, Y_pred, labels=[0, 1]).ravel()
        tnr = tn / (tn + fp)
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        tpr = tp / (tp + fn)

        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time),
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': '{:05.4f}'.format(accuracy), 'F1Score': '{:05.4f}'.format(f1),
               'TPR': '{:05.4f}'.format(tpr), 'FPR': '{:05.4f}'.format(fpr), 'TNR': '{:05.4f}'.format(tnr), 'FNR': '{:05.4f}'.format(fnr), 'Source': data_source}
    else:
        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time),
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': "N/A", 'F1Score': "N/A",
               'TPR': "N/A", 'FPR': "N/A", 'TNR': "N/A", 'FNR': "N/A", 'Source': data_source}
    pprint.pprint(row, sort_dicts=False)
    writer.writerow(row)

if __name__ == "__main__":
    main(sys.argv[1:])
