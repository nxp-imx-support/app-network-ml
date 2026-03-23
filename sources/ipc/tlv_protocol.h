// Copyright 2025 NXP
// SPDX-License-Identifier: BSD-3-Clause

#ifndef TLV_PROTOCOL_H
#define TLV_PROTOCOL_H

#include <stdint.h>

// TLV Message Types
#define MSG_TYPE_PACKET_FEATURES  0x01
#define MSG_TYPE_DETECTION_RESULT 0x02
#define MSG_TYPE_HEARTBEAT        0x03

// TLV Header: Type(2B) + Length(4B)
#define TLV_HEADER_SIZE 6

typedef struct {
    uint16_t type;
    uint32_t length;
} __attribute__((packed)) tlv_header_t;

// Packet Feature Structure (46 bytes)
typedef struct {
    uint64_t timestamp;      // 8 bytes
    uint8_t src_mac[6];      // 6 bytes
    uint8_t dst_mac[6];      // 6 bytes
    uint16_t protocol_type;  // 2 bytes (0x0800=IPv4, 0x86DD=IPv6)
    uint32_t src_ip;         // 4 bytes
    uint32_t dst_ip;         // 4 bytes
    uint8_t transmission_type; // 1 byte (6=TCP, 17=UDP, 1=ICMP)
    uint16_t src_port;       // 2 bytes
    uint16_t dst_port;       // 2 bytes
    uint16_t packet_size;    // 2 bytes
    uint8_t tcp_flags;       // 1 byte
    uint16_t padding;        // 2 bytes (alignment)
} __attribute__((packed)) packet_feature_t;

// Detection Result Structure (16 bytes)
typedef struct {
    uint64_t timestamp;      // 8 bytes
    uint8_t is_attack;       // 1 byte (0=benign, 1=attack)
    uint8_t confidence;      // 1 byte (0-100)
    uint16_t padding;        // 2 bytes
    uint32_t flow_id;        // 4 bytes
} __attribute__((packed)) detection_result_t;

#endif // TLV_PROTOCOL_H
