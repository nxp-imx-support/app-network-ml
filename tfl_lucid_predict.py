import pprint
import csv
import os
import h5py
import numpy as np
import glob
# import tensorflow as tf
import tflite_runtime.interpreter as tflite
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix
import argparse
import time

OUTPUT_FOLDER = "./output/"
PREDICT_HEADER = ['Model', 'Time', 'Packets', 'Samples', 'DDOS%', 'Accuracy', 'F1Score', 'TPR', 'FPR','TNR', 'FNR', 'Source']
DEFAULT_EPOCHS = 100

def load_dataset(path):
    filename = glob.glob(path)[0]
    dataset = h5py.File(filename, "r")
    set_x_orig = np.array(dataset["set_x"][:])  # features
    set_y_orig = np.array(dataset["set_y"][:])  # labels

    X_train = np.reshape(set_x_orig, (set_x_orig.shape[0], set_x_orig.shape[1], set_x_orig.shape[2], 1))
    Y_train = set_y_orig#.reshape((1, set_y_orig.shape[0]))

    return X_train, Y_train


def count_packets_in_dataset(X_list):
    packet_counters = []
    for X in X_list:
        TOT = X.sum(axis=2)
        packet_counters.append(np.count_nonzero(TOT))
    return packet_counters

def main():
    help_string = 'Usage: python3 lucid_cnn.py --train <dataset_folder> -e <epocs>'

    parser = argparse.ArgumentParser(
        description='DDoS attacks detection with convolutional neural networks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-a', '--attack_net', default=None, type=str,
                        help='Subnet of the attacker (used to compute the detection accuracy)')

    parser.add_argument('-v', '--victim_net', default=None, type=str,
                        help='Subnet of the victim (used to compute the detection accuracy)')

    parser.add_argument('-p', '--predict', nargs='?', type=str,
                        help='Perform a prediction on pre-preprocessed data')

    parser.add_argument('-pl', '--predict_live', nargs='?', type=str,
                        help='Perform a prediction on live traffic')

    parser.add_argument('-i', '--iterations', default=1, type=int,
                        help='Predict iterations')

    parser.add_argument('-m', '--model', type=str,
                        help='File containing the model')

    parser.add_argument('-y', '--dataset_type', default=None, type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019, SYN2020')

    parser.add_argument(
      '-e', '--ext_delegate', help='external_delegate_library path')
    
    parser.add_argument(
      '-o',
      '--ext_delegate_options',
      help='external delegate options, \
            format: "option1: value1; option2: value2"')
    
    args = parser.parse_args()

    if os.path.isdir(OUTPUT_FOLDER) == False:
        os.mkdir(OUTPUT_FOLDER)

    predict(args)


def predict(args):
    # args.predict: ./sample-dataset/
    # args.model: ./output/10t-10n-DOS2019-LUCID.tflite
    predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
    predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
    predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
    predict_writer.writeheader()
    predict_file.flush()

    ext_delegate = None
    ext_delegate_options = {}

    iterations = args.iterations
    # ['./sample-dataset/10t-10n-DOS2019-dataset-test.hdf5']
    dataset_filelist = glob.glob(args.predict + "/*test.hdf5")

    # load external delegate
    if args.ext_delegate is not None:
        print('Loading external delegate from {} with args: {}'.format(
            args.ext_delegate, ext_delegate_options))
        ext_delegate = [
            tflite.load_delegate(args.ext_delegate, ext_delegate_options)
        ]

    if args.model is not None:
        model_list = [args.model]
    else:
        model_list = glob.glob(args.predict + "/*.h5")
    # model_path: ./output/10t-10n-DOS2019-LUCID.tflite
    for model_path in model_list:
        # 10t-10n-DOS2019-LUCID.tflite
        model_filename = model_path.split('/')[-1].strip()
        # 10t-10n
        filename_prefix = model_filename.split('-')[0].strip() + '-' + model_filename.split('-')[1].strip() + '-'
        # DOS2019-LUCID
        model_name_string = model_filename.split(filename_prefix)[1].strip().split('.')[0].strip()
        # model = tf.lite.Interpreter(model_path=model_path)
        model = tflite.Interpreter(model_path=model_path, experimental_delegates=ext_delegate)
        model.allocate_tensors()

        input_desc = model.get_input_details()[0]
        output_desc = model.get_output_details()[0]

        print("input_desc_type {}".format(input_desc['dtype']))
        input_scale, input_zero_point = input_desc['quantization']
        print("input_scale: {}; input_zero_point: {}".format(input_scale, input_zero_point))
        
        # warming up the model (necessary for the GPU)
        warm_up_file = dataset_filelist[0]
        filename = warm_up_file.split('/')[-1].strip()
        if filename_prefix in filename:
            X, Y = load_dataset(warm_up_file)
            Y_pred = list()
            cnt = 0
            for vec in X:
                if cnt > 10:
                    break
                input_data = vec / input_scale + input_zero_point
                input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
                model.set_tensor(input_desc['index'], input_data)
                model.invoke()
                tmp = np.squeeze(model.get_tensor(output_desc['index']))
                tmp = input_scale * (tmp - input_zero_point)
                Y_pred.append(tmp > 0.5)
                cnt += 1

        # 正式预测
        for dataset_file in dataset_filelist:
            filename = dataset_file.split('/')[-1].strip()
            if filename_prefix in filename:
                X, Y = load_dataset(dataset_file)
                [packets] = count_packets_in_dataset([X])

                Y_pred = list()
                Y_true = Y
                avg_time = 0
                pt0 = time.time()
                for vec in X:
                    input_data = vec / input_scale + input_zero_point
                    input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
                    model.set_tensor(input_desc['index'], input_data)
                    model.invoke()
                    tmp = np.squeeze(model.get_tensor(output_desc['index']))
                    tmp = input_scale * (tmp - input_zero_point)
                    Y_pred.append(tmp > 0.5)
                Y_pred = np.array(Y_pred)
                avg_time = time.time() - pt0

                report_results(np.squeeze(Y_true), Y_pred, packets, model_name_string, filename, avg_time,predict_writer)
                predict_file.flush()
    predict_file.close()


def report_results(Y_true, Y_pred, packets, model_name, data_source, prediction_time, writer):
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

        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': '{:05.4f}'.format(accuracy), 'F1Score': '{:05.4f}'.format(f1),
               'TPR': '{:05.4f}'.format(tpr), 'FPR': '{:05.4f}'.format(fpr), 'TNR': '{:05.4f}'.format(tnr), 'FNR': '{:05.4f}'.format(fnr), 'Source': data_source}
    else:
        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': "N/A", 'F1Score': "N/A",
               'TPR': "N/A", 'FPR': "N/A", 'TNR': "N/A", 'FNR': "N/A", 'Source': data_source}
    pprint.pprint(row, sort_dicts=False)
    writer.writerow(row)


if __name__ == "__main__":
    main()
    # X, Y = load_dataset("./sample-dataset/10t-10n-DOS2019-dataset-test.hdf5")
    # print(X[0])