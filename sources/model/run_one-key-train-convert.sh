#! /bin/bash
# Run this script on Linux Host to train and convert the model. 
# Finally, it copy the tflite model to DST_PATH to execute neutron-convert

EPOCHS="1000"
PD_MODEL="../../output/LUCID-ddos-CIC2019"
TFL_MODEL="../../output/LUCID-ddos-CIC2019-quant-int8.tflite"
DST_PATH="~/Code/learning_code/python_code/eiq_convert/tfl_models"

python3 lucid_cnn.py --train ../../sample-dataset/  --epochs ${EPOCHS}
sleep 3
python3 lucid_convert.py ${PD_MODEL} ${TFL_MODEL} ../../sample-dataset/dataset_train.hdf5
sleep 1
cp -r ${TFL_MODEL} ${DST_PATH}