# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

CC ?= aarch64-poky-linux-gcc
CFLAGS = -Wall -Wextra -I../common -O2

OBJ = socket_manager.o

.PHONY: all clean

all: $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ)
