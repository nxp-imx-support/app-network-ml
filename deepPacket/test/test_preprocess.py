import sys
sys.path.append("..")
import preprocess
import numpy as np
import time

def test_parse_pcap():
    flow_list = dict()
    preprocess.parse_pcap("/opt/Dataset/NXP-Traff/email01.pcap", 5000, None, flow_list)

    t_cnt = 0
    cnt = 0
    for k, v in flow_list.items():
        if len(v.pkt_list) > 15:
            cnt += 1
        t_cnt += 1

    print(cnt, t_cnt, sep=',')

def test_extract_feature():
    flow_list = dict()
    preprocess.parse_pcap("/opt/Dataset/NXP-Traff/email01.pcap", 5000, None, flow_list)
    
    t1 = time.time()
    cnt = 0
    for k, v in flow_list.items():
        ret = preprocess.extract_feature(v, 8, "test")
        cnt += len(ret)
        # print(ret)
        # break
    print("extract_feature time: {:.2f}, sample count: {}".format(time.time() - t1, cnt))

if __name__ == '__main__':
    test_extract_feature()