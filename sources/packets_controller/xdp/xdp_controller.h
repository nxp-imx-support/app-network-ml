/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_controller.h
 * Brief: XDP controller interface for packets_controller
 */

#ifndef XDP_CONTROLLER_H
#define XDP_CONTROLLER_H

#include <stdint.h>

typedef struct {
    uint8_t protocol;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
} flow_rule_t;

int xdp_init(const char *ifname, const char *prog_file);
void xdp_cleanup(void);
int xdp_read_packet_feature(void *feat);
int xdp_update_blacklist(const flow_rule_t *rule);
int xdp_update_whitelist(const flow_rule_t *rule);

#endif
