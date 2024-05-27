#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/ipv6.h>
#include <time.h>
#include <vector>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>

#define V4_FLOW_KEY_SIZE 2
#define V6_FLOW_KEY_SIZE 6
#define IPV6_ADDR_LEN 16
#define TCP_PROTOCOL_NUM 6
#define UDP_PROTOCOL_NUM 17
#define ICMP_PROTOCOL_NUM 1
#define ICMPV6_PROTOCOL_NUM 58

const __u16 PROSTACK_ETH = 1;
const __u16 PROSTACK_IP = 1 << 1;
const __u16 PROSTACK_TCP = 1 << 2;
const __u16 PROSTACK_UDP = 1 << 3;
const __u16 PROSTACK_ICMP = 1 << 4;
const __u16 PROSTACK_SSL = 1 << 5;
const __u16 PROSTACK_HTTP = 1 << 6;
const __u16 PROSTACK_DNS = 1 << 7;

// const uint64_t v4_key_mask[V4_FLOW_KEY_SIZE] = { 0x00FF0000FFFFFFFF, 0xFFFFFFFFFFFFFFFF };
const uint64_t v4_key_mask[V4_FLOW_KEY_SIZE] = { 0xFFFFFFFF0000FF00, 0xFFFFFFFFFFFFFFFF };
const uint64_t v6_key_mask[V6_FLOW_KEY_SIZE] = { 0xFFFFFFFF00FF0000, 0xFFFFFFFFFFFFFFFF, 
                                                 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                                 0xFFFFFFFFFFFFFFFF, 0x0};

// If the number of pakcets in a flow > flow_len, call the AI inference process.
const size_t flow_len_threshold = 24;
// Max packets in a time window.
const size_t win_max_pkt = 10;
// Time period (second) in a time window.
const int win_time_period = 10;

/**
 * IPv4 flow table key
*/
union v4_flow_key {
    struct {
        uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
    };
    uint64_t block[V4_FLOW_KEY_SIZE];
};

/**
 * IPv4 packet information
*/
struct v4_packet_info {
    // five-tuple
    union v4_flow_key flow_key;
    bool is_valid_flow_key;
    // Information for parse stack
    __u8 ip_hdr_len;
    __u16 ip_payload_length;
    __u8 proto_val;
    __u8 trans_hdr_len;     // Transmission layer info
    
    // Features list
    struct timeval ts;
    __u32 packet_length;    // Entire packet length
    __u16 flags;        // IP Flags
    __u16 highest_layer;     // Highest layer
    __u16 protocols_stack;        // Protocol stack
    __u32 tcp_len;      // TCP Len
    __u32 tcp_ack;      // TCP Ack num
    __u8 tcp_flags;      // TCP Flags
    __u16 tcp_win;      // TCP Window Size
    __u32 udp_len;      // UDP Len
    __u8 icmp_type;     // ICMP Type
};

// Ordered by features list in v4_packet_info
const uint32_t feature_value_range[][2] = {{0, 10}, 
                                           {0, 0xFFFFFFFF}, 
                                           {0, 0xFFFF},
                                           {0, 0xFFFF},
                                           {0, 0xFFFF},
                                           {0, 0xFFFFFFFF},
                                           {0, 0xFFFFFFFF},
                                           {0, 0xFF},
                                           {0, 0xFFFF},
                                           {0, 0xFFFFFFFF},
                                           {0, 0xFF}};

/**
 * IPv6 flow table key
*/
union v6_flow_key {
    struct {
		uint16_t pad0;
		uint8_t  proto;
		uint8_t  pad1;
		uint8_t  ip_src[IPV6_ADDR_LEN];
		uint8_t  ip_dst[IPV6_ADDR_LEN];
		uint16_t port_src;
		uint16_t port_dst;
		uint64_t reserve;
	};
	uint8_t block[V6_FLOW_KEY_SIZE];
};

/**
 * IPv6 packet information
*/
struct v6_packet_info {
    // five-tuple
    union v6_flow_key flow_key;
    bool is_valid_flow_key;
    // Information for parse stack
    __u8 ip_hdr_len;
    __u16 ip_payload_length;
    __u8 proto_val;
    
    // Features list
    struct timeval ts;
    __u32 packet_length;    // Entire packet length
    __u16 flags;        // IP Flags
    __u8 trans_hdr_len;     // Transmission layer info
    char highest_layer[10];     // Highest layer
    __u16 protocols_stack;        // Protocol stack
    __u32 tcp_len;      // TCP Len
    __u32 tcp_ack;      // TCP Ack num
    __u8 tcp_flags;      // TCP Flags
    __u16 tcp_win;      // TCP Window Size
    __u32 udp_len;      // UDP Len
    __u8 icmp_type;     // ICMP Type
};


// struct packet_list {
//     std::vector<packet_info> vec;
// };

// struct packet_info* alloc_packet_info();
// void free_packet_info(struct packet_info* ptr);

// int extract_ip_layer(const u_char* pkt_data, int ip_ver, struct packet_info* pkt_info);
// int extract_transmission_layer(const u_char* pkt_data, int trans_type, struct packet_info* pkt_info);

// void print_packet_info(struct packet_info* pkt_info);

struct v4_packet_info* alloc_v4_packet_info();

void free_v4_packet_info(struct v4_packet_info* ptr);

/**
 * Handle network protocol stack, extract packet information and 5-tuple. Match the packet
 *  to flow table
 * @param pkt: packet from mbuf
 * @param l3ptype: L3 protocol type
 * @param l4ptype: L4 protocol type
 * @retval void
*/
void handle_protocol_stack(struct rte_mbuf *pkt);

/**
 * Startup a new thread. Preprocess flow table and send it to AI inference process via pipe
*/
void flow_table_inference();

/**
 * Clean up v4 flow table
*/
void v4_flow_table_cleanup();

/**
 * Clean up v6 flow table
*/
void v6_flow_table_cleanup();

void print_v4_flow_table();
void insert_v4_flow_table(struct v4_packet_info* v4_pkt);