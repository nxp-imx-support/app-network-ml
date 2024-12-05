/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "dpdk-l2capfwd.h"

int main(int argc, char** argv) {
    // Load and parse configuration file.
    configuration_items cfgs;
    int ret = parse_configuration(CONFIGRATION_FILE, cfgs);
    if (ret < 0)
        return -1;

    // Execute dpdk_l2capfwd
    dpdk_l2capfwd_main(argc, argv, cfgs);
    return 0;
}