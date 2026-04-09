import sys
import numpy as np
sys.path.insert(0, '../imx_board')

from board_inference import LucidCNNBoardModel
from util_functions import load_dataset, calculate_metrics

feature_value_range = [
    [0, 10],
    [0, 0xFFFF],
    [0, 0x0F],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFFFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFFFF],
    [0, 0xFF]
]

x_test, y_test = load_dataset("../../../sample-dataset/dataset_test.hdf5")

pkt_array = x_test.reshape((-1, 11))
ret_list = list()
for row in pkt_array:
    tmp = list()
    for i, f in enumerate(row):
        tmp.append(f * (feature_value_range[i][1] - feature_value_range[i][0]) + feature_value_range[i][0])
    
    print("=" * 60)
    print("packet features:")
    print("diff_ts={}".format(tmp[0]))
    print("l2_length={}".format(tmp[1]))
    print("ip_flags={}".format(tmp[2]))
    print("l4_type={}".format(tmp[3]))
    print("l3_type+l4_type={}".format(tmp[4]))
    print("tcp_length={}".format(tmp[5]))
    print("tcp_ack={}".format(tmp[6]))
    print("tcp_flags={}".format(tmp[7]))
    print("tcp_win={}".format(tmp[8]))
    print("udp_len={}".format(tmp[9]))
    print("icmp_type={}".format(tmp[10]))
    print("=" * 60)


model = LucidCNNBoardModel("../../../output/LUCID-ddos-CIC2019-quant-int8.tflite", (-1, 10, 11, 1))

y_tmp = model.predict(x_test)

y_pred = list()
for y in y_tmp:
    if y > 0.5:
        y_pred.append(1)
    else:
        y_pred.append(0)
y_pred = np.array(y_pred)

print(y_pred)
accuracy, precision, recall, f1, tp, fp, fn, tn = calculate_metrics(y_test, y_pred)


print("\n===== Evaluation Metrics =====")
print("Confusion Matrix:")
print("  TP: {}, FP: {}".format(tp, fp))
print("  FN: {}, TN: {}".format(fn, tn))
print("Accuracy:  {:.4f}".format(accuracy))
print("Precision: {:.4f}".format(precision))
print("Recall:    {:.4f}".format(recall))
print("F1 Score:  {:.4f}".format(f1))