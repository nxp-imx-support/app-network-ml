/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_controller.h
 * Brief: XDP controller interface for packets_controller
 */

#ifndef XDP_CONTROLLER_H
#define XDP_CONTROLLER_H

#include <stdint.h>

#define STATS_IDX_RX      0
#define STATS_IDX_PASS    1
#define STATS_IDX_DROP    2
#define STATS_IDX_SUBMIT  3

int xdp_init(const char *ifnames[], int ifcount, const char *monitor_ifname, const char *prog_file);
void xdp_cleanup(void);
int xdp_read_packet_feature(void *feat);
int xdp_update_blacklist(const uint32_t src_ip);
int xdp_update_whitelist(const uint32_t ip_addr);
int xdp_get_stats(uint64_t *rx, uint64_t *pass, uint64_t *drop, uint64_t *submit);
int xdp_get_blacklist_count(void);
int xdp_get_blacklist_ips(uint32_t *ips, int max_count);

#endif