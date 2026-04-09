// Copyright 2025 NXP
// SPDX-License-Identifier: BSD-3-Clause

#ifndef TLV_PROTOCOL_H
#define TLV_PROTOCOL_H

#include <stdint.h>

// TLV Message Types
#define MSG_TYPE_PACKET_FEATURES  0x01
#define MSG_TYPE_DETECTION_RESULT 0x02

// TLV Header: Type(2B) + Length(4B)
#define TLV_HEADER_SIZE 6

#define MAX_RESULT_ENTRIES 100000
#define MAX_DETECTION_RESULT_SIZE (sizeof(uint32_t) + MAX_RESULT_ENTRIES * sizeof(result_entry_t))

typedef struct {
    uint16_t type;
    uint32_t length;
} __attribute__((packed)) tlv_header_t;

typedef struct {
    uint8_t protocol;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint32_t is_attack;
    uint32_t confidence;
} __attribute__((packed)) result_entry_t;

typedef struct {
    uint32_t ret_size;
    result_entry_t entries[];
} __attribute__((packed)) detection_result_t;

#endif // TLV_PROTOCOL_H
