/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: stats.h
 * Brief: Statistics reporting for packets_controller
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>

#define MAX_BLACKLIST_DISPLAY 200
#define MAX_TOP_CONNECTIONS 1000
#define HASH_TABLE_SIZE 4096

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

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t l4_type;
    uint64_t packet_count;
} connection_entry_t;

typedef struct {
    connection_entry_t entries[MAX_TOP_CONNECTIONS];
    int count;
} connection_report_t;

void stats_init_connection_table(void);
void stats_update_connection(uint32_t src_ip, uint16_t src_port,
                             uint32_t dst_ip, uint16_t dst_port,
                             uint8_t l4_type);
int stats_get_connections_for_report(connection_report_t *report);
void stats_cleanup_connection_table(void);

int stats_write_report(const char *path, const stats_report_t *report);

#endif