import sys
sys.path.append("..")
import api
import time

def test_parse_dp_report():
    ret = api.parse_dp_report("/home/nxg01813/Code/deepPacket-TF/output_dir/2023-12-27_01-04-54.pickle")
    print(ret.class_counter)

def test_generate_dp_response():
    t1 = time.time()
    print(api.generate_dp_response())
    t1 = time.time() - t1
    print("time cost: {}s".format(t1))

if __name__ == '__main__':
    test_generate_dp_response()
    # test_parse_dp_report()