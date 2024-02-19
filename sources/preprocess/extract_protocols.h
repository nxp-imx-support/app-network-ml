#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <time.h>
#include <vector>

const __u16 PROSTACK_ETH = 1;
const __u16 PROSTACK_IP = 1 << 1;
const __u16 PROSTACK_TCP = 1 << 2;
const __u16 PROSTACK_UDP = 1 << 3;
const __u16 PROSTACK_ICMP = 1 << 4;
const __u16 PROSTACK_SSL = 1 << 5;
const __u16 PROSTACK_HTTP = 1 << 6;
const __u16 PROSTACK_DNS = 1 << 7;

struct packet_info {
    // five-tuple
    char src_ip[46];
    char dst_ip[46];
    __u16 src_port;
    __u16 dst_port;
    char proto_type[4];
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

struct packet_list {
    std::vector<packet_info> vec;
};

struct packet_info* alloc_packet_info();
void free_packet_info(struct packet_info* ptr);

int extract_ip_layer(const u_char* pkt_data, int ip_ver, struct packet_info* pkt_info);
int extract_transmission_layer(const u_char* pkt_data, int trans_type, struct packet_info* pkt_info);

void print_packet_info(struct packet_info* pkt_info);