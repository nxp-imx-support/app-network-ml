#!/bin/bash
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Copy files to specified path to facilitate deployment on the board.

# Modify this path if you need
DST_DIR=board_deploy
IMXDDB_DEPLOY_DIR=${DST_DIR}/imx-ddb
VICTIM_DEPLOY_DIR=${DST_DIR}/victim_webser
echo "Dest path:${DST_DIR}"

if [ ! -d $(realpath ${DST_DIR}) ]; then
  echo "Creating the deploy folder: ${DST_DIR}"
  mkdir $DST_DIR
else
  rm -r ${DST_DIR}/*
fi

if [ ! -d ${IMXDDB_DEPLOY_DIR} ]; then
  echo "Craeting ${IMXDDB_DEPLOY_DIR}"
  mkdir ${IMXDDB_DEPLOY_DIR}
fi

if [ ! -d ${VICTIM_DEPLOY_DIR} ]; then
  echo "Craeting ${VICTIM_DEPLOY_DIR}"
  mkdir ${VICTIM_DEPLOY_DIR}
fi

if [ ! -d "${IMXDDB_DEPLOY_DIR}/model" ]; then
  echo "Creating model folder"
  mkdir ${IMXDDB_DEPLOY_DIR}/model
fi

if [ ! -d "${IMXDDB_DEPLOY_DIR}/webui" ]; then
  echo "Create Web UI folder"
  mkdir ${IMXDDB_DEPLOY_DIR}/webui
fi

echo "Copy executable programs and models"
cp sources/build/l2capfwd ${IMXDDB_DEPLOY_DIR}
cp sources/build/config.json ${IMXDDB_DEPLOY_DIR}
cp sources/ipc/libshmanager.so ${IMXDDB_DEPLOY_DIR}
cp sources/model/model_inference_main.py ${IMXDDB_DEPLOY_DIR}/model
cp -r sources/webui/* ${IMXDDB_DEPLOY_DIR}/webui/
cp output/LUCID-ddos-CIC2019-quant-int8.tflite ${IMXDDB_DEPLOY_DIR}/model
# cp run_demo.py ${IMXDDB_DEPLOY_DIR}
cp run_demo.sh ${IMXDDB_DEPLOY_DIR}
cp sources/requirements-for-board.txt ${IMXDDB_DEPLOY_DIR}

echo "Copy victim web server"
cp -r sources/victim_webser/* ${VICTIM_DEPLOY_DIR}

echo "Finish."
