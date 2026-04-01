#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define MAC_ADDRESS_LENGTH 6

#define PAD_BUFFER_SIZE 7

typedef struct {
    uint64_t timestamp;
    uint8_t src_mac[MAC_ADDRESS_LENGTH];
    uint8_t dst_mac[MAC_ADDRESS_LENGTH];
    uint16_t l3_type;
    uint32_t l2_length;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ip_flags;
    uint8_t l4_type;
    uint32_t l3_length;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t tcp_flags;
    uint32_t tcp_ack;
    uint16_t tcp_win;
    uint8_t icmp_type;
    uint32_t l4_length;
    uint8_t pad[PAD_BUFFER_SIZE];
} __attribute__((packed)) packet_feature_t;

#endif // COMMON_H