/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_kern.h
 * Brief: Data stuctrue in XDP kernel program
 * 
 */

#define MAX_FLOWS 10000
#define MAC_ADDRESS_LENGTH 6
#define PAD_BUFFER_SIZE 7

#define STATS_IDX_RX      0
#define STATS_IDX_PASS    1
#define STATS_IDX_DROP    2
#define STATS_IDX_SUBMIT  3
#define STATS_MAP_SIZE    4

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, __u32);
    __type(value, __u32);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 200);
} packet_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} ifindex_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} monitor_ifindex_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Let some control protocl pass
__u16 pass_ports[] = {137, 138, 139};