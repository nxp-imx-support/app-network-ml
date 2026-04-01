# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC = gcc
CLANG = clang
CFLAGS = -Wall -O2
BPF_CFLAGS = -target bpf -O2 -g

BUILD_DIR = build
IPC_DIR = ipc
XDP_DIR = xdp

.PHONY: all clean xdp

all: $(BUILD_DIR)/libsocketmanager.so $(BUILD_DIR)/xdp_controller $(BUILD_DIR)/xdp_forward_kern.o

# Socket manager library
$(BUILD_DIR)/libsocketmanager.so: $(IPC_DIR)/socket_manager.c $(IPC_DIR)/socket_manager.h $(IPC_DIR)/tlv_protocol.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(IPC_DIR)/socket_manager.c

# XDP kernel program
$(BUILD_DIR)/xdp_forward_kern.o: $(XDP_DIR)/xdp_forward_kern.c | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# XDP controller
$(BUILD_DIR)/xdp_controller: $(XDP_DIR)/xdp_controller.c $(BUILD_DIR)/libsocketmanager.so | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(IPC_DIR) -L$(BUILD_DIR) -o $@ $< -lsocketmanager -lbpf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
