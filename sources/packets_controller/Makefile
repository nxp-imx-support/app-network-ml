# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I./common -I./ipc -I./xdp -O2

IPC_DIR = ./ipc
IPC_OBJ = $(IPC_DIR)/socket_manager.o

XDP_DIR = ./xdp
XDP_OBJ = $(XDP_DIR)/xdp_controller.o

BUILD_DIR = build
TARGET = $(BUILD_DIR)/packets_controller_main
SRC = packets_controller_main.c

.PHONY: all clean

all: $(IPC_OBJ) $(XDP_OBJ) $(TARGET)

$(IPC_OBJ):
	$(MAKE) -C $(IPC_DIR)

$(XDP_OBJ):
	$(MAKE) -C $(XDP_DIR)

$(TARGET): $(BUILD_DIR)/packets_controller_main.o $(IPC_OBJ) $(XDP_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(IPC_OBJ) $(XDP_OBJ)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(IPC_DIR) clean
	$(MAKE) -C $(XDP_DIR) clean
