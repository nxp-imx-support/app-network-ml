#!/bin/bash

DST_DIR=/home/nxg01813/Board_bak/i.MX95/dpdk-ddos-intercept
echo "Dest path:$DST_DIR"

if [ ! -d $DST_DIR ]; then
  echo "You need to create this folder manually: $DST_DIR"
  exit
fi

if [ ! -d "$DST_DIR/model" ]; then
  echo "Create model folder"
  mkdir $DST_DIR/model
fi

if [ ! -d "$DST_DIR/webui" ]; then
  echo "Create Web UI folder"
  mkdir $DST_DIR/webui
fi

echo "Copy executable programs and models"
cp sources/build/l2capfwd $DST_DIR
cp sources/model/model_inference_main.py $DST_DIR/model
cp -r sources/webui/* $DST_DIR/webui/
cp output/LUCID-ddos-CIC2019-quant-int8.tflite $DST_DIR/model
cp run_demo.sh $DST_DIR
cp run_demo_imx95.sh $DST_DIR
echo "Finish."
