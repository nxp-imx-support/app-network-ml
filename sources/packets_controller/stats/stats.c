/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: stats.c
 * Brief: Statistics reporting implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "stats.h"

static uint32_t connection_count_total = 0;
static connection_entry_t hash_table[HASH_TABLE_SIZE];

static uint32_t connection_hash(uint32_t src_ip, uint16_t src_port,
                                uint32_t dst_ip, uint16_t dst_port,
                                uint8_t l4_type) {
    uint32_t h1 = src_ip;
    uint16_t h2 = src_port;
    uint32_t h3 = dst_ip;
    uint16_t h4 = dst_port;
    if (src_port < dst_port || (src_port == dst_port && src_ip < dst_ip)) {
        h1 = dst_ip;
        h2 = dst_port;
        h3 = src_ip;
        h4 = src_port;
    }

    return (h1 ^ h2 ^ h3 ^ h4 ^ l4_type) % HASH_TABLE_SIZE;
}

void stats_init_connection_table(void) {
    memset(hash_table, 0, sizeof(hash_table));
    connection_count_total = 0;
}

void stats_update_connection(uint32_t src_ip, uint16_t src_port,
                             uint32_t dst_ip, uint16_t dst_port,
                             uint8_t l4_type) {
    uint32_t hash = connection_hash(src_ip, src_port, dst_ip, dst_port, l4_type);
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        uint32_t idx = (hash + i) % HASH_TABLE_SIZE;
        
        if (hash_table[idx].packet_count == 0) {
            hash_table[idx].src_ip = src_ip;
            hash_table[idx].src_port = src_port;
            hash_table[idx].dst_ip = dst_ip;
            hash_table[idx].dst_port = dst_port;
            hash_table[idx].l4_type = l4_type;
            hash_table[idx].packet_count = 1;
            connection_count_total++;
            return;
        } else if (hash_table[idx].src_ip == src_ip &&
                   hash_table[idx].src_port == src_port &&
                   hash_table[idx].dst_ip == dst_ip &&
                   hash_table[idx].dst_port == dst_port &&
                   hash_table[idx].l4_type == l4_type) {
            hash_table[idx].packet_count++;
            return;
        }
    }
}

int stats_get_connections_for_report(connection_report_t *report) {
    if (!report) return -1;
    
    report->count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (hash_table[i].packet_count > 0 && report->count < MAX_TOP_CONNECTIONS) {
            report->entries[report->count++] = hash_table[i];
        }
    }
    
    for (int i = 0; i < report->count - 1; i++) {
        for (int j = i + 1; j < report->count; j++) {
            if (report->entries[i].packet_count < report->entries[j].packet_count) {
                connection_entry_t temp = report->entries[i];
                report->entries[i] = report->entries[j];
                report->entries[j] = temp;
            }
        }
    }
    
    return report->count;
}

void stats_cleanup_connection_table(void) {
    memset(hash_table, 0, sizeof(hash_table));
    connection_count_total = 0;
}

int stats_write_report(const char *path, const stats_report_t *report)
{
    char tmp_path[512];
    FILE *f;
    int i;

    if (!path || !report) {
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    f = fopen(tmp_path, "w");
    if (!f) {
        fprintf(stderr, "Stats: Failed to open %s for writing\n", tmp_path);
        return -1;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"timestamp\": %lu,\n", (unsigned long)report->timestamp_ms);
    fprintf(f, "  \"xdp_rx_packets\": %lu,\n", (unsigned long)report->xdp_rx_packets);
    fprintf(f, "  \"xdp_pass_packets\": %lu,\n", (unsigned long)report->xdp_pass_packets);
    fprintf(f, "  \"xdp_drop_packets\": %lu,\n", (unsigned long)report->xdp_drop_packets);
    fprintf(f, "  \"xdp_submit_packets\": %lu,\n", (unsigned long)report->xdp_submit_packets);
    fprintf(f, "  \"blacklist_count\": %u,\n", report->blacklist_count);
    fprintf(f, "  \"blacklist_updates\": %u,\n", report->blacklist_updates);
    fprintf(f, "  \"blacklist_count_total\": %u,\n", report->blacklist_count_total);

    fprintf(f, "  \"blacklist_ips\": [\n");
    for (i = 0; i < (int)report->blacklist_count && i < MAX_BLACKLIST_DISPLAY; i++) {
        struct in_addr addr;
        char ip_str[INET_ADDRSTRLEN];
        addr.s_addr = report->blacklist_ips[i];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        
        if (i < (int)report->blacklist_count - 1 && i < MAX_BLACKLIST_DISPLAY - 1) {
            fprintf(f, "    \"%s\",\n", ip_str);
        } else {
            fprintf(f, "    \"%s\"\n", ip_str);
        }
    }
    fprintf(f, "  ],\n");
    
    connection_report_t conn_report;
    int conn_count = stats_get_connections_for_report(&conn_report);
    fprintf(f, "  \"connection_count\": %u,\n", conn_count);

    if (conn_count > 0) {
        fprintf(f, "  \"connections\": [\n");
        
        for (i = 0; i < conn_count; i++) {
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            
            struct in_addr addr;
            addr.s_addr = conn_report.entries[i].src_ip;
            inet_ntop(AF_INET, &addr, src_ip_str, sizeof(src_ip_str));
            
            addr.s_addr = conn_report.entries[i].dst_ip;
            inet_ntop(AF_INET, &addr, dst_ip_str, sizeof(dst_ip_str));
            
            if (i < conn_count - 1) {
                fprintf(f, "    {\"src_ip\": \"%s\", \"src_port\": %u, \"dst_ip\": \"%s\", \"dst_port\": %u, \"l4_type\": %u, \"packet_count\": %lu},\n",
                        src_ip_str, conn_report.entries[i].src_port, dst_ip_str,
                        conn_report.entries[i].dst_port, conn_report.entries[i].l4_type,
                        (unsigned long)conn_report.entries[i].packet_count);
            } else {
                fprintf(f, "    {\"src_ip\": \"%s\", \"src_port\": %u, \"dst_ip\": \"%s\", \"dst_port\": %u, \"l4_type\": %u, \"packet_count\": %lu}\n",
                        src_ip_str, conn_report.entries[i].src_port, dst_ip_str,
                        conn_report.entries[i].dst_port, conn_report.entries[i].l4_type,
                        (unsigned long)conn_report.entries[i].packet_count);
            }
        }
        
        fprintf(f, "  ]\n");
    } else {
        fprintf(f, "  \"connections\": []\n");
    }
    
    fprintf(f, "}\n");

    fclose(f);

    if (rename(tmp_path, path) != 0) {
        fprintf(stderr, "Stats: Failed to rename %s to %s\n", tmp_path, path);
        return -1;
    }

    return 0;
}