/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "utils.h"
#include <cstring>
#include <array>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>

using MacAddress = std::array<uint8_t, 6>;
using IPv4Address = uint32_t;

static const MacAddress INVALID_MAC{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

class ArpTable {
public:
    void add_entry(const std::string& ip_str, const std::string& mac_str) {
        IPv4Address ip = 0;
        inet_pton(AF_INET, ip_str.c_str(), &ip);
        MacAddress mac = parse_mac(mac_str);
        table[ip] = mac;
    }

    const MacAddress* lookup(const IPv4Address ip_addr) const {
        auto it = table.find(ip_addr);
        if (it != table.end()) {
            return &it->second;
        }
        return nullptr;
    }
private:
    std::unordered_map<IPv4Address, MacAddress> table;

    MacAddress parse_mac(const std::string& mac_str) const {
        MacAddress mac{};
        std::istringstream iss(mac_str);
        std::string byte_str;
        int i = 0;

        while (std::getline(iss, byte_str, ':') && i < 6) {
            mac[i++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }

        if (i != 6) {
            LOG_ERROR("Invalid MAC address format: %s", mac_str.c_str());
            return INVALID_MAC;
        }

        return mac;
    }
};

int dpdk_l2capfwd_main(int argc, char **argv, configuration_items& cfgs);