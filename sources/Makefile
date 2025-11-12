# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

#
# Makefile
#

# binary name
APP = l2capfwd

# all source are stored in SRCS-y
SRC-h := preprocess/utils.h preprocess/extract_protocols.h preprocess/dpdk-l2capfwd.h
SRCS-y := preprocess/dpdk-l2capfwd.cpp preprocess/main.cpp preprocess/extract_protocols.cpp preprocess/utils.cpp
# SRCS-test := preprocess/test.cpp preprocess/extract_protocols.cpp preprocess/utils.cpp

PKGCONF ?= pkg-config
INCLUDE_PATH := ./ipc
LIB_PATH := ./ipc

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: static debug
.PHONY: static test debug
static: build/$(APP)
# test: build/test
debug: build/$(APP)-debug

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
# Add flag to allow experimental API as l2fwd uses rte_ethdev_set_ptype API
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif


build/$(APP): $(SRCS-y) $(PC_FILE) $(SRC-h) | build
	$(CXX) $(CFLAGS) $(SRCS-y) -I $(INCLUDE_PATH) -L $(LIB_PATH) -lshmanager -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)
	cp ./preprocess/config.json ./build/
	cp ./ipc/libshmanager.so ./build/

build/test: $(SRCS-test) $(SRC-h) | build
	$(CXX) $(CFLAGS) $(SRCS-test) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build/$(APP)-debug: $(SRCS-y) $(PC_FILE) $(SRC-h) | build
	$(CXX) $(CFLAGS) -g $(SRCS-y) -I $(INCLUDE_PATH) -L $(LIB_PATH) -lshmanager -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)
	cp ./preprocess/config.json ./build/
	cp ./ipc/libshmanager.so ./build/

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf build
