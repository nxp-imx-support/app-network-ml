/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: stats.h
 * Brief: Statistics reporting for packets_controller
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>

#define MAX_BLACKLIST_DISPLAY 100

typedef struct {
    uint64_t xdp_rx_packets;
    uint64_t xdp_pass_packets;
    uint64_t xdp_drop_packets;
    uint64_t xdp_submit_packets;
    uint32_t blacklist_count;
    uint32_t blacklist_updates;
    uint32_t blacklist_count_total;
    uint32_t blacklist_ips[MAX_BLACKLIST_DISPLAY];
    uint64_t timestamp_ms;
} stats_report_t;

int stats_write_report(const char *path, const stats_report_t *report);

#endif
