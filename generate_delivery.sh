#!/bin/bash
PLATFORM=i.MX95
echo "Target platform is $PLATFORM"

# Modify this path if you need
DST_DIR=~/Board_bak/$PLATFORM/imx-ddb
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
cp sources/build/config.json $DST_DIR
cp sources/model/model_inference_main.py $DST_DIR/model
cp -r sources/webui/* $DST_DIR/webui/
cp output/LUCID-ddos-CIC2019-quant-int8.tflite $DST_DIR/model
cp run_demo.py $DST_DIR
echo "Finish."
