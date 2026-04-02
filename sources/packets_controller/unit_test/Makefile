# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

# Cross-compilation for ARM (requires sourcing environment setup script):
#   $ source /opt/fsl-imx-xwayland/6.12-styhead/environment-setup-armv8a-poky-linux
#   $ make

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I../common -I../ipc -I../xdp -O2

IPC_DIR = ../ipc
IPC_OBJ = $(IPC_DIR)/socket_manager.o

XDP_DIR = ../xdp
XDP_OBJ = $(XDP_DIR)/xdp_controller.o

LDFLAGS = -lbpf

BUILD_DIR = build
IPC_TEST = $(BUILD_DIR)/test_ipc_integration
XDP_TEST = $(BUILD_DIR)/test_xdp_controller

.PHONY: all clean

all: $(IPC_TEST) $(XDP_TEST)

$(IPC_TEST): test_ipc_integration.c $(IPC_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(XDP_TEST): test_xdp_controller.c $(IPC_OBJ) $(XDP_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(IPC_OBJ):
	$(MAKE) -C $(IPC_DIR)

$(XDP_OBJ):
	$(MAKE) -C $(XDP_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(IPC_DIR) clean
	$(MAKE) -C $(XDP_DIR) clean