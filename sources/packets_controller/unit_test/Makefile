# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

# Cross-compilation for ARM (requires sourcing environment setup script):
#   $ source /opt/fsl-imx-xwayland/6.12-styhead/environment-setup-armv8a-poky-linux
#   $ make

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I../common -I../ipc -O2
LDFLAGS =

IPC_DIR = ../ipc
IPC_OBJ = $(IPC_DIR)/socket_manager.o

BUILD_DIR = build
TARGET = $(BUILD_DIR)/test_ipc_integration
SRC = test_ipc_integration.c

.PHONY: all clean

all: $(IPC_OBJ) $(TARGET)

$(IPC_OBJ):
	$(MAKE) -C $(IPC_DIR)

$(TARGET): $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(IPC_OBJ) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(IPC_DIR) clean
