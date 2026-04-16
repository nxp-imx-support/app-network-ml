# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I../common -I../ipc -I../xdp -O2

TARGET = stats.o
SRC = stats.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET)