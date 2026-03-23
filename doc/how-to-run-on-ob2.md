# How to run on OranageBox2.0 board

## Model quan­ti­za­tion and con­ver­sion

Convert to tflite model:
```
python3 model_manager.py -c /home/uh3ng/Code/my-imx-ddos-blocker/output/LUCID-CNN-ddos-CIC2019.keras /home/uh3ng/Code/my-imx-ddos-blocker/output/LUCID-CNN-ddos-CIC2019-quant-int8.tflite /home/uh3ng/Code/my-imx-ddos-blocker/sample-dataset/dataset_train.hdf5
```

Download eiq-neutron-sdk from [here](https://www.nxp.com/design/design-center/software/eiq-ai-development-environment/eiq-toolkit-for-end-to-end-model-development-and-deployment:EIQ-TOOLKIT)

```
export LD_LIBRARY_PATH=/home/uh3ng/SDK/eiq-neutron-sdk-linux-3.0.1/lib

cd bin

./neutron-converter --input /home/uh3ng/Code/my-imx-ddos-blocker/output/LUCID-CNN-ddos-CIC2019-quant-int8.tflite --target imx943 --output /home/uh3ng/Code/my-imx-ddos-blocker/output/LUCID-CNN-ddos-CIC2019-quant-int8-imx943-npu.tflite --min-num-ops-per-graph 1 --dump-statistics --verbose
```
