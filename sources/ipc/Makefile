# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

#
# Makefile
#

.PHONY: all libshm clean
all: libshm
libshm: shm_manager.c shm_manager.h
	$(GCC) shm_manager.c -shared -fPIC -o libshmanager.so
	
clean:
	rm libshmanager.so