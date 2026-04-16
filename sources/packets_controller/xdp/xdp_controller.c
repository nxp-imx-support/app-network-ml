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
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/sysinfo.h>

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
static int stats_map_fd = -1;
static struct ring_buffer *rb = NULL;
static packet_feature_t pending_pkt;
static volatile int has_pending = 0;

int ringbuf_callback(void *ctx, void *data, size_t len) 
{
    (void)ctx;

    if (len != sizeof(packet_feature_t)) {
        fprintf(stderr, "XDP: Invalid packet size: %zu\n", len);
        return 0;
    }
    
    memcpy(&pending_pkt, data, sizeof(packet_feature_t));
    has_pending = 1;
    
    return 1;  // Stop processing next packet
}

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

    rb = ring_buffer__new(ringbuf_fd, ringbuf_callback, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "XDP: Failed to create ring buffer\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

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

    map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!map) {
        fprintf(stderr, "XDP: Failed to find stats_map\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }
    stats_map_fd = bpf_map__fd(map);

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
        err = bpf_xdp_attach(ifindexes[i], prog_fd, XDP_FLAGS_SKB_MODE, NULL);
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

    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    ringbuf_fd = -1;
    whitelist_map_fd = -1;
    blacklist_map_fd = -1;
    ifindex_map_fd = -1;
    monitor_ifindex_map_fd = -1;
    stats_map_fd = -1;
}

int xdp_read_packet_feature(void *feat)
{
    if (!rb) {
        return -1;
    }
    
    has_pending = 0;
    
    // timeout = 100ms
    int err = ring_buffer__poll(rb, 100);
    
    if (err < 0) {
        fprintf(stderr, "XDP: ring_buffer__poll error: %d\n", err);
        return -1;
    }
    
    if (!has_pending)
        return -2;  // Timeout
    
    memcpy(feat, &pending_pkt, sizeof(packet_feature_t));
    return 0;
}

int xdp_update_blacklist(const uint32_t src_ip)
{
    uint32_t val = 1;
    int err;

    if (blacklist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_update_elem(blacklist_map_fd, &src_ip, &val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update blacklist: %d\n", err);
        return -1;
    }

    return 0;
}

int xdp_update_whitelist(const uint32_t ip_addr)
{
    uint32_t val = 1;
    int err;

    if (whitelist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_update_elem(whitelist_map_fd, (void*)&ip_addr, &val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "XDP: Failed to update whitelist: %d\n", err);
        return -1;
    }

    return 0;
}

int xdp_get_stats(uint64_t *rx, uint64_t *pass, uint64_t *drop, uint64_t *submit)
{
    int ncpus;
    uint64_t *values;
    uint64_t total;
    __u32 idx;
    int i;

    if (stats_map_fd < 0) {
        return -1;
    }

    ncpus = get_nprocs();
    if (ncpus <= 0) {
        return -1;
    }

    values = malloc(ncpus * sizeof(uint64_t));
    if (!values) {
        return -1;
    }

    total = 0;
    idx = STATS_IDX_RX;
    if (bpf_map_lookup_elem(stats_map_fd, &idx, values) == 0) {
        for (i = 0; i < ncpus; i++) {
            total += values[i];
        }
    }
    if (rx) *rx = total;

    total = 0;
    idx = STATS_IDX_PASS;
    if (bpf_map_lookup_elem(stats_map_fd, &idx, values) == 0) {
        for (i = 0; i < ncpus; i++) {
            total += values[i];
        }
    }
    if (pass) *pass = total;

    total = 0;
    idx = STATS_IDX_DROP;
    if (bpf_map_lookup_elem(stats_map_fd, &idx, values) == 0) {
        for (i = 0; i < ncpus; i++) {
            total += values[i];
        }
    }
    if (drop) *drop = total;

    total = 0;
    idx = STATS_IDX_SUBMIT;
    if (bpf_map_lookup_elem(stats_map_fd, &idx, values) == 0) {
        for (i = 0; i < ncpus; i++) {
            total += values[i];
        }
    }
    if (submit) *submit = total;

    free(values);
    return 0;
}

int xdp_get_blacklist_count(void)
{
    int count = 0;
    uint32_t key = 0, next_key;
    int err;

    if (blacklist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_get_next_key(blacklist_map_fd, NULL, &next_key);
    while (err == 0) {
        count++;
        key = next_key;
        err = bpf_map_get_next_key(blacklist_map_fd, &key, &next_key);
    }

    return count;
}

int xdp_get_blacklist_ips(uint32_t *ips, int max_count)
{
    int count = 0;
    uint32_t key = 0, next_key;
    int err;

    if (!ips || max_count <= 0 || blacklist_map_fd < 0) {
        return -1;
    }

    err = bpf_map_get_next_key(blacklist_map_fd, NULL, &next_key);
    while (err == 0 && count < max_count) {
        ips[count] = next_key;
        count++;
        key = next_key;
        err = bpf_map_get_next_key(blacklist_map_fd, &key, &next_key);
    }

    return count;
}