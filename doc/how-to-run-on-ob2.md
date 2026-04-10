# How to run on OranageBox2.0 board

**You can start from the step 3 if you do not want to train the model**. This repository also provides a pre-trained model in `output` folder.

## Step 1: Model training
Setup the training environment:
```bash
pip3 install -r sources/requirements-for-pc.txt
```

Tr­ain the mod­el us­ing the pro­vid­ed train­ing script:
```bash
cd sources/ml_detector
python3 model_manager.py -m lucid_cnn -t ../../sample-dataset -e 200
```

**Only lucid_cnn model is supported for now**

## Step 2: Model quan­ti­za­tion and con­ver­sion

Convert to tflite model:
```
python3 model_manager.py -c ../../output/LUCID-CNN-ddos-CIC2019.keras ../../output/LUCID-CNN-ddos-CIC2019-quant-int8.tflite ../../sample-dataset/dataset_train.hdf5
```

Download eiq-neutron-sdk from [here](https://www.nxp.com/design/design-center/software/eiq-ai-development-environment/eiq-toolkit-for-end-to-end-model-development-and-deployment:EIQ-TOOLKIT)

```bash
export LD_LIBRARY_PATH=<your eiq path>/eiq-neutron-sdk-linux-3.0.1/lib

cd bin

./neutron-converter --input <your imx-ddb path>/output/LUCID-CNN-ddos-CIC2019-quant-int8.tflite --target imx943 --output <your imx-ddb path>/output/LUCID-CNN-ddos-CIC2019-quant-int8-imx943-npu.tflite --min-num-ops-per-graph 1 --dump-statistics --verbose
```

## Step 3: Build board deploy package
Install the yocto toolchain in your host syste­m and set the TOOLCHAIN variable, for example:
```bash
TOOLCHAIN_PATH=/opt/fsl-imx-xwayland/6.12-styhead/environment-setup-armv8a-poky-linux ./build_and_install.sh
```

You will get the `board_deploy` folder. Then, copy this folder to the OrangeBox2.0 board.

## Step 4: Running on the board
On orangebox2.0 board, navigate to the `board_deploy` folder and run:
```bash
python3 run_imx-ddb.py
```
