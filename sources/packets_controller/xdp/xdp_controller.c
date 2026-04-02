/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_controller.c
 * Brief: Userspace XDP controller stub functions
 *
 * NOTE: This is a stub implementation. The actual XDP functionality
 * requires libbpf headers which are not available in the current
 * cross-compilation environment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xdp_controller.h"
#include "../common/common.h"
#include "../ipc/tlv_protocol.h"

int xdp_init(const char *ifname, const char *prog_file)
{
    (void)ifname;
    (void)prog_file;
    fprintf(stderr, "XDP init: STUB (not functional)\n");
    return 0;
}

void xdp_cleanup(void)
{
}

int xdp_read_packet_feature(void *feat)
{
    (void)feat;
    return -1;
}

int xdp_update_blacklist(const flow_rule_t *rule)
{
    (void)rule;
    return 0;
}

int xdp_update_whitelist(const flow_rule_t *rule)
{
    (void)rule;
    return 0;
}
