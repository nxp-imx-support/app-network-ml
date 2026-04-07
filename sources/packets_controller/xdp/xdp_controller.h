/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_controller.h
 * Brief: XDP controller interface for packets_controller
 */

#ifndef XDP_CONTROLLER_H
#define XDP_CONTROLLER_H

#include <stdint.h>

int xdp_init(const char *ifnames[], int ifcount, const char *monitor_ifname, const char *prog_file);
void xdp_cleanup(void);
int xdp_read_packet_feature(void *feat);
int xdp_update_blacklist(const uint32_t src_ip);
int xdp_update_whitelist(const uint32_t ip_addr);

#endif