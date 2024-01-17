import sys
sys.path.append("..")
from tfl_predict import InferenceReport, TrafficFlowResult
import pickle

fd = open("../inference_report.pickle", "rb")
inference_report = pickle.load(fd)
fd.close()

print(inference_report.warmup_time)
print(inference_report.inference_time)
print(inference_report.effective_flow_cnt)