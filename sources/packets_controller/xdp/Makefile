# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I../common -I../ipc -O2
CLANG ?= clang --sysroot=$(SDKTARGETSYSROOT)
CL_FLAGS := -g -O3 -target bpf -D__aarch64__ -D__KERNEL__ -D__BPF__ -Wall -I../common

BUILD_DIR = ../build

.PHONY: all clean

all: xdp_controller.o xdp_forward_kern.o

xdp_controller.o: xdp_controller.c xdp_controller.h
	$(CC) $(CFLAGS) -c -o $@ $<

xdp_forward_kern.o: xdp_forward_kern.c
	$(CLANG) $(CL_FLAGS) -c $^ -o $@

clean:
	rm -f xdp_controller.o
	rm -f xdp_forward_kern.o
