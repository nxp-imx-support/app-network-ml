/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_controller.c
 * Brief: Userspace XDP controller functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_controller.h"
#include "../common/common.h"
#include "../ipc/tlv_protocol.h"

static struct bpf_object *obj = NULL;
static int ifindexes[2] = {-1, -1};
static int ifcount = 0;
static int whitelist_map_fd = -1;
static int blacklist_map_fd = -1;
static int ifindex_map_fd = -1;
static int monitor_ifindex_map_fd = -1;
static int ringbuf_fd = -1;
static struct pollfd xdp_pollfd;

int xdp_init(const char *ifnames[], int ifcount_arg, const char *monitor_ifname, const char *prog_file)
{
    struct bpf_map *map;
    struct bpf_program *prog;
    int prog_fd;
    int err;

    if (ifcount_arg < 1 || ifcount_arg > 2) {
        fprintf(stderr, "XDP: Invalid interface count (must be 1 or 2)\n");
        return -1;
    }
    ifcount = ifcount_arg;

    obj = bpf_object__open_file(prog_file, NULL);
    if (!obj) {
        fprintf(stderr, "XDP: Failed to open BPF file: %s\n", prog_file);
        return -1;
    }

    err = bpf_object__load(obj);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    map = bpf_object__find_map_by_name(obj, "packet_ringbuf");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find packet_ringbuf map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    ringbuf_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "whitelist_map");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find whitelist_map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    whitelist_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "blacklist_map");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find blacklist_map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    blacklist_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "ifindex_map");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find ifindex_map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    ifindex_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "monitor_ifindex_map");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find monitor_ifindex_map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    monitor_ifindex_map_fd = bpf_map__fd(map);

    prog = bpf_object__find_program_by_name(obj, "xdp_forward_prog");
    if (!prog) {
        fprintf(stderr, "XDP: Failed to find xdp_forward_prog\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    for (int i = 0; i < ifcount; i++) {
        ifindexes[i] = if_nametoindex(ifnames[i]);
        if (ifindexes[i] == 0) {
            fprintf(stderr, "XDP: Failed to get interface index: %s\n", ifnames[i]);
            bpf_object__close(obj);
            obj = NULL;
            return -1;
        }
    }

    __u32 idx = 0;
    err = bpf_map_update_elem(ifindex_map_fd, &idx, &ifcount, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update ifindex_map ifcount: %d\n", err);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    for (int i = 0; i < ifcount; i++) {
        idx = i + 1;
        err = bpf_map_update_elem(ifindex_map_fd, &idx, &ifindexes[i], BPF_ANY);
        if (err < 0) {
            fprintf(stderr, "XDP: Failed to update ifindex_map ifindex[%d]: %d\n", i, err);
            bpf_object__close(obj);
            obj = NULL;
            return -1;
        }
    }

    uint32_t monitor_ifindex = if_nametoindex(monitor_ifname);
    if (monitor_ifindex == 0) {
        fprintf(stderr, "XDP: Failed to get monitor interface index: %s\n", monitor_ifname);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    uint32_t monitor_val = 1;
    err = bpf_map_update_elem(monitor_ifindex_map_fd, &monitor_ifindex, &monitor_val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update monitor_ifindex_map: %d\n", err);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    for (int i = 0; i < ifcount; i++) {
        err = bpf_xdp_attach(ifindexes[i], prog_fd, 0, NULL);
        if (err < 0) {
            fprintf(stderr, "XDP: Failed to attach XDP to %s: %d\n", ifnames[i], err);
            for (int j = 0; j < i; j++) {
                bpf_xdp_detach(ifindexes[j], 0, NULL);
            }
            bpf_object__close(obj);
            obj = NULL;
            return -1;
        }
    }

    xdp_pollfd.fd = ringbuf_fd;
    xdp_pollfd.events = POLLIN;

    fprintf(stderr, "XDP: Initialized with %d interface(s)\n", ifcount);
    for (int i = 0; i < ifcount; i++) {
        fprintf(stderr, "  - %s (ifindex=%d)\n", ifnames[i], ifindexes[i]);
    }
    fprintf(stderr, "XDP: Monitor interface: %s (ifindex=%u)\n", monitor_ifname, monitor_ifindex);
    return 0;
}

void xdp_cleanup(void)
{
    for (int i = 0; i < ifcount; i++) {
        if (ifindexes[i] > 0) {
            bpf_xdp_detach(ifindexes[i], 0, NULL);
            ifindexes[i] = -1;
        }
    }
    ifcount = 0;

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    ringbuf_fd = -1;
    whitelist_map_fd = -1;
    blacklist_map_fd = -1;
    ifindex_map_fd = -1;
    monitor_ifindex_map_fd = -1;
}

int xdp_read_packet_feature(void *feat)
{
    int ret;

    if (ringbuf_fd < 0) {
        return -1;
    }

    ret = poll(&xdp_pollfd, 1, 100);
    if (ret <= 0) {
        return -1;
    }

    if (xdp_pollfd.revents & POLLIN) {
        ssize_t len = read(ringbuf_fd, feat, sizeof(packet_feature_t));
        if (len == sizeof(packet_feature_t)) {
            return 0;
        }
    }

    return -1;
}

int xdp_update_blacklist(const flow_rule_t *rule)
{
    uint32_t val = 1;
    int err;

    if (blacklist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_update_elem(blacklist_map_fd, rule, &val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update blacklist: %d\n", err);
        return -1;
    }

    return 0;
}

int xdp_update_whitelist(const flow_rule_t *rule)
{
    uint32_t val = 1;
    int err;

    if (whitelist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_update_elem(whitelist_map_fd, rule, &val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update whitelist: %d\n", err);
        return -1;
    }

    return 0;
}