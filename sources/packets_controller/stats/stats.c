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
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    fclose(f);

    if (rename(tmp_path, path) != 0) {
        fprintf(stderr, "Stats: Failed to rename %s to %s\n", tmp_path, path);
        return -1;
    }

    return 0;
}
