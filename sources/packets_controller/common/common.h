#include <stdint.h>

#define MAC_ADDRESS_LENGTH 6

// Packet Feature Structure
typedef struct {
    uint64_t timestamp;
    // Layer 2
    uint8_t src_mac[MAC_ADDRESS_LENGTH];
    uint8_t dst_mac[MAC_ADDRESS_LENGTH];
    uint16_t l3_type;
    uint32_t l2_length;
    // Layer 3
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ip_flags;
    uint8_t l4_type;
    uint32_t l3_length;
    // Layer 4
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t tcp_flags;
    uint32_t tcp_ack;
    uint16_t tcp_window;
    uint8_t icmp_type;
    uint32_t l4_length;
} __attribute__((packed)) packet_feature_t;