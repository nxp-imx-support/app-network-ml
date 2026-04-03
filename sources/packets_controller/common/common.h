#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

#define MAC_ADDRESS_LENGTH 6

#define PAD_BUFFER_SIZE 7

typedef struct {
    __u64 timestamp;
    __u8 src_mac[MAC_ADDRESS_LENGTH];
    __u8 dst_mac[MAC_ADDRESS_LENGTH];
    __u16 l3_type;
    __u32 l2_length;
    __u32 src_ip;
    __u32 dst_ip;
    __u8 ip_flags;
    __u8 l4_type;
    __u32 l3_length;
    __u16 src_port;
    __u16 dst_port;
    __u16 tcp_flags;
    __u32 tcp_ack;
    __u16 tcp_win;
    __u8 icmp_type;
    __u32 l4_length;
    __u8 pad[PAD_BUFFER_SIZE];
} __attribute__((packed)) packet_feature_t;

#endif // COMMON_H