#!/bin/bash
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

DST_DIR=board_deploy
IMXDDB_DEPLOY_DIR=${DST_DIR}/imx-ddb

echo "Creating deployment package..."

rm -rf ${DST_DIR}
mkdir -p ${IMXDDB_DEPLOY_DIR}/model
mkdir -p ${IMXDDB_DEPLOY_DIR}/webui

echo "Copying XDP programs..."
cp sources/build/xdp_forward_kern.o ${IMXDDB_DEPLOY_DIR}/
cp sources/build/xdp_controller ${IMXDDB_DEPLOY_DIR}/
cp sources/build/libsocketmanager.so ${IMXDDB_DEPLOY_DIR}/

echo "Copying Python inference code..."
cp sources/model/model_inference_main_refactored.py ${IMXDDB_DEPLOY_DIR}/model/
cp sources/model/socket_ipc.py ${IMXDDB_DEPLOY_DIR}/model/
cp sources/model/feature_converter.py ${IMXDDB_DEPLOY_DIR}/model/
cp sources/model/board_inference.py ${IMXDDB_DEPLOY_DIR}/model/

echo "Copying models..."
cp output/LUCID-ddos-CIC2019-quant-int8.tflite ${IMXDDB_DEPLOY_DIR}/model/

echo "Copying WebUI..."
cp -r sources/webui/* ${IMXDDB_DEPLOY_DIR}/webui/

echo "Copying scripts..."
cp run_demo.sh ${IMXDDB_DEPLOY_DIR}/
cp sources/requirements-for-board.txt ${IMXDDB_DEPLOY_DIR}/

echo "Done. Deploy with: scp -r ${IMXDDB_DEPLOY_DIR} root@<board_ip>:/home/root/"
