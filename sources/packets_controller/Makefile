# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I./common -I./ipc -I./xdp -I./stats -O2
LDFLAGS = -lbpf

IPC_DIR = ./ipc
IPC_OBJ = $(IPC_DIR)/socket_manager.o

XDP_DIR = ./xdp
XDP_OBJ = $(XDP_DIR)/xdp_controller.o

STATS_DIR = ./stats
STATS_OBJ = $(STATS_DIR)/stats.o

BUILD_DIR = build
TARGET = $(BUILD_DIR)/packets_controller_main
SRC = packets_controller_main.c
LDFLAGS ?= -lbpf

.PHONY: all clean

all: $(IPC_OBJ) $(XDP_OBJ) $(STATS_OBJ) $(TARGET)

$(IPC_OBJ):
	$(MAKE) -C $(IPC_DIR)

$(XDP_OBJ):
	$(MAKE) -C $(XDP_DIR)

$(STATS_OBJ):
	$(MAKE) -C $(STATS_DIR)

$(TARGET): $(BUILD_DIR)/packets_controller_main.o $(IPC_OBJ) $(XDP_OBJ) $(STATS_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(IPC_OBJ) $(XDP_OBJ) $(STATS_OBJ) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(IPC_DIR) clean
	$(MAKE) -C $(XDP_DIR) clean
	$(MAKE) -C $(STATS_DIR) clean
