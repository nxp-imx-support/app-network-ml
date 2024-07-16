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
from lucid_dataset_parser import process_live_traffic, dataset_to_list_of_fragments
from util_functions import static_min_max, normalize_and_padding

OUTPUT_FOLDER = "../../output/"
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


def load_tfl_model(path, ext_delegate, ext_opt):
    ext_dele = None
    if ext_delegate is not None:
        print("Loading external delegate from {} with options: {}".format(ext_delegate, ext_opt))
        ext_dele = [tflite.load_delegate(ext_delegate, ext_opt)]

    model = tflite.Interpreter(model_path=path, experimental_delegates=ext_dele)
    return model


def main():

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

    if args.predict is not None:
        predict(args)
    elif args.predict_live is not None:
        predict_live(args)

def inference_process(model, X):
    model.allocate_tensors()
    input_desc = model.get_input_details()[0]
    output_desc = model.get_output_details()[0]
    print("input_desc_type {}".format(input_desc['dtype']))
    input_scale, input_zero_point = input_desc['quantization']
    print("input_scale: {}; input_zero_point: {}".format(input_scale, input_zero_point))

    cnt = 0
    # warmup
    for vec in X:
        if cnt > 10:
            break
        # input_data = vec / input_scale + input_zero_point
        # input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
        input_data = np.expand_dims(vec, axis=0).astype(input_desc["dtype"])
        model.set_tensor(input_desc['index'], input_data)
        model.invoke()
        cnt += 1

    # start inference
    Y_pred = list()
    avg_time = 0
    delta = 0
    
    tmp_log = open("tmp_log.txt", "w")
    print("open log.")
    for vec in X:
        # input_data = vec / input_scale + input_zero_point
        # input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
        input_data = np.expand_dims(vec, axis=0).astype(input_desc["dtype"])
        model.set_tensor(input_desc['index'], input_data)
        pt0 = time.time()
        model.invoke()
        delta = time.time() - pt0
        tmp = np.squeeze(model.get_tensor(output_desc['index']))
        init_tmp = tmp
        # tmp = input_scale * (tmp - input_zero_point)
        tmp_log.write("init tmp: {}, tmp: {}\n".format(init_tmp, tmp))
        Y_pred.append(tmp > 0.5)
        avg_time += delta
    Y_pred = np.array(Y_pred)
    tmp_log.close()
    return Y_pred, avg_time


def predict(args):
    # args.predict: ./sample-dataset/
    # args.model: ./output/10t-10n-DOS2019-LUCID.tflite
    predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
    predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
    predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
    predict_writer.writeheader()
    predict_file.flush()

    ext_delegate_options = {}
    # ['./sample-dataset/10t-10n-DOS2019-dataset-test.hdf5']
    dataset_filelist = glob.glob(args.predict)
    print(dataset_filelist)

    if args.model is not None:
        model_path = args.model
    else:
        print ("No valid model specified!")
        exit(-1)
    # model_path: ./output/10t-10n-DOS2019-LUCID.tflite
    # 10t-10n-DOS2019-LUCID.tflite
    model_filename = model_path.split('/')[-1].strip()
    # model = tf.lite.Interpreter(model_path=model_path)
    model = load_tfl_model(model_path, args.ext_delegate, ext_delegate_options)
    
    # warming up the model (necessary for the GPU)
    warm_up_file = dataset_filelist[0]
    X, Y = load_dataset(warm_up_file)

    Y_pred, avg_time = inference_process(model, X)
    [packets] = count_packets_in_dataset([X])
    report_results(Y, Y_pred, packets, model_path, dataset_filelist, avg_time, predict_writer)
'''
    for vec in X:
        if cnt > 10:
            break
        # input_data = vec / input_scale + input_zero_point
        # input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
        model.set_tensor(input_desc['index'], input_data)
        model.invoke()
        tmp = np.squeeze(model.get_tensor(output_desc['index']))
        tmp = input_scale * (tmp - input_zero_point)
        Y_pred.append(tmp > 0.5)
        cnt += 1

    # Start inference
    for dataset_file in dataset_filelist:
        filename = dataset_file.split('/')[-1].strip()
        X, Y = load_dataset(dataset_file)
        [packets] = count_packets_in_dataset([X])

        Y_pred = list()
        Y_true = Y
        avg_time = 0
        delta = 0
        
        for vec in X:
            input_data = vec / input_scale + input_zero_point
            input_data = np.expand_dims(input_data, axis=0).astype(input_desc["dtype"])
            model.set_tensor(input_desc['index'], input_data)
            pt0 = time.time()
            model.invoke()
            delta = time.time() - pt0
            tmp = np.squeeze(model.get_tensor(output_desc['index']))
            tmp = input_scale * (tmp - input_zero_point)
            Y_pred.append(tmp > 0.5)
            avg_time += delta
        Y_pred = np.array(Y_pred)

        report_results(np.squeeze(Y_true), Y_pred, packets, model_filename, filename, avg_time,predict_writer)
        predict_file.flush()
    predict_file.close()
'''

def predict_live(args):
    predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
    predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
    predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
    predict_writer.writeheader()
    predict_file.flush()

    if args.predict_live is None:
        print("Please specify a valid network interface!")
        exit(-1)
    else:
        cap = args.predict_live
        data_source = args.predict_live

    print ("Prediction on network traffic from: ", data_source)

    # load the labels, if available
    # labels = parse_labels(args.dataset_type, args.attack_net, args.victim_net)
    labels = None

    # do not forget command sudo ./jetson_clocks.sh on the TX2 board before testing
    if args.model is not None:
        model_path = args.model
    else:
        print ("No valid model specified!")
        exit(-1)

    model_filename = model_path.split('/')[-1].strip()
    filename_prefix = model_filename.split('n')[0] + 'n-'
    time_window = int(filename_prefix.split('t-')[0])
    max_flow_len = int(filename_prefix.split('t-')[1].split('n-')[0])
    model_name_string = model_filename.split(filename_prefix)[1].strip().split('.')[0].strip()
    ext_delegate_options = {}
    model = load_tfl_model(model_path, args.ext_delegate, ext_delegate_options)

    mins, maxs = static_min_max(time_window)

    while (True):
        samples = process_live_traffic(cap, args.dataset_type, labels, max_flow_len, traffic_type="all", time_window=time_window)
        if len(samples) > 0:
            X,Y_true,keys = dataset_to_list_of_fragments(samples)
            X = np.array(normalize_and_padding(X, mins, maxs, max_flow_len))

            X = np.expand_dims(X, axis=3)
            pt0 = time.time()
            Y_pred = inference_process(model, X)
            pt1 = time.time()
            prediction_time = pt1 - pt0

            [packets] = count_packets_in_dataset([X])
            report_results(np.squeeze(Y_true), Y_pred, packets, model_name_string, data_source, prediction_time,predict_writer)
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
