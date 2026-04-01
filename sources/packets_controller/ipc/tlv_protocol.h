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

typedef struct {
    uint16_t type;
    uint32_t length;
} __attribute__((packed)) tlv_header_t;

// Detection Result Structure
typedef struct {
    
} __attribute__((packed)) detection_result_t;

#endif // TLV_PROTOCOL_H
