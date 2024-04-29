#include "extract_protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdlib.h>
#include <unordered_map>
#include <sys/time.h>

std::unordered_map<int, std::vector<struct v4_packet_info*>> v4_flow_table;
std::unordered_map<int, std::vector<struct v6_packet_info*>> v6_flow_table;
uint64_t cnt;

struct v4_packet_info* alloc_v4_packet_info() {
    struct v4_packet_info* ptr = (v4_packet_info*)malloc(sizeof(struct v4_packet_info));
    if (ptr) {
        memset(ptr, 0, sizeof(struct v4_packet_info));
        return ptr;
    }
    return NULL;
}

void free_v4_packet_info(struct v4_packet_info* ptr) {
    if (ptr) {
        free(ptr);
        ptr = NULL;
    }
}

void print_v4_packet_info(struct v4_packet_info* v4_pkt) {
    printf("=====packet begin======\n");
    printf("pkt information:\n time stamp: %lu:%lu, packet length: %d\n", 
        v4_pkt->ts.tv_sec, v4_pkt->ts.tv_usec, v4_pkt->packet_length);
    
    char src_ip[16] = { 0 };
	char dst_ip[16] = { 0 };
	inet_ntop(AF_INET, (void*)(&v4_pkt->flow_key.ip_src), src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, (void*)(&v4_pkt->flow_key.ip_dst), dst_ip, sizeof(dst_ip));
    int flag = v4_pkt->is_valid_flow_key ? 1 : 0;
    printf("is flow key valid? %d, flow key: (%s:%d->%s:%d, %d)\n", flag, src_ip, ntohs(v4_pkt->flow_key.port_src), 
        dst_ip, ntohs(v4_pkt->flow_key.port_dst), v4_pkt->flow_key.proto);
    
    printf("ip header length: %u, ip payload length: %u, proto val: %u\n", 
        v4_pkt->ip_hdr_len, v4_pkt->ip_payload_length, v4_pkt->proto_val);
    printf("trans hdr length: %u, highest layer: %u, protocols stack: %x\n",
        v4_pkt->trans_hdr_len, v4_pkt->highest_layer, v4_pkt->protocols_stack);
    printf("tcp length: %u, tcp ack: %u, tcp flags: %u, tcp windows: %u\n",
        v4_pkt->tcp_len, v4_pkt->tcp_ack, v4_pkt->tcp_flags, v4_pkt->tcp_win);
    printf("udp length: %u\n", v4_pkt->udp_len);
    printf("icmp type: %u\n", v4_pkt->icmp_type);
    printf("=====packet end=====\n");
}

void print_v6_packet_info(struct v6_packet_info* v6_pkt) {
    return;
}

/**
 * Note: It is not a standard judgement method for Ether frame. 
 * In the case, we only support TYPE=IPv4/IPv6
*/
static inline int 
is_valid_ether_pkt(struct rte_ether_hdr *pkt, uint32_t pkt_len) {
    // 1. The packet length need to be bigger than rte_ether_hdr
    if (pkt_len < sizeof(struct rte_ether_hdr))
        return -1;
    uint16_t eth_type = ntohs(pkt->ether_type);
    // 2. The type need to be IPv4 or IPv6
    if (eth_type != RTE_ETHER_TYPE_IPV4 && 
        eth_type != RTE_ETHER_TYPE_IPV6)
        return -1;
    return 0;
}

static inline int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct rte_ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;

	return 0;
}

static bool
is_valid_ipv6_pkt(const struct rte_ipv6_hdr *pkt)
{
	/* The IP version number must be 6 */
	if ((rte_be_to_cpu_32((pkt->vtc_flow)) >> 28) != 6)
		return false;

	return true;
}

// Make sure that src port > dst port
void order_trans_ports(void* flow_key, bool is_ipv4) {
    if (is_ipv4) {
        union v4_flow_key* flow_key_ptr = (union v4_flow_key*)flow_key;
        if (flow_key_ptr->port_src < flow_key_ptr->port_dst) {
            // Swap src and dst ports
            uint16_t tmp_port = flow_key_ptr->port_src;
            flow_key_ptr->port_src = flow_key_ptr->port_dst;
            flow_key_ptr->port_dst = tmp_port;

            uint32_t tmp_ip = flow_key_ptr->ip_dst;
            flow_key_ptr->ip_dst = flow_key_ptr->ip_src;
            flow_key_ptr->ip_src = tmp_ip;
        }
    } else {

    }
}

void handle_protocol_stack(struct rte_mbuf *pkt) {
    cnt += 1;
    printf("No#%lu\n", cnt);
    // Point to protocol header fileds
    uint8_t* pro_ptr = NULL;

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (is_valid_ether_pkt(eth_hdr, pkt->pkt_len) < 0) {
        rte_pktmbuf_free(pkt);
        printf("invalid ehter packet.\n");
        return;
    }
    pro_ptr = (uint8_t*)eth_hdr;
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct rte_ipv6_hdr *ipv6_hdr = NULL;

    struct v4_packet_info* v4_pkt = NULL;
    struct v6_packet_info* v6_pkt = NULL;

    // Handle IPv4 and IPv6
    if (eth_type == RTE_ETHER_TYPE_IPV4) {
        ipv4_hdr = (struct rte_ipv4_hdr*)(pro_ptr + sizeof(struct rte_ether_hdr));
	
        if (int ret = is_valid_ipv4_pkt(ipv4_hdr, pkt->pkt_len) < 0) {
            printf("invalid ipv4 packet. error code: %d\n", ret);
            rte_pktmbuf_free(pkt);
            return;
        }

        v4_pkt = alloc_v4_packet_info();
        gettimeofday(&v4_pkt->ts, NULL);
        v4_pkt->packet_length = pkt->pkt_len;
        v4_pkt->ip_hdr_len = (ipv4_hdr->ihl & 0xF) << 2;
        v4_pkt->ip_payload_length = ntohs(ipv4_hdr->total_length) - v4_pkt->ip_hdr_len;
        v4_pkt->proto_val = ipv4_hdr->next_proto_id;
        v4_pkt->flags = ipv4_hdr->fragment_offset;
        v4_pkt->protocols_stack = PROSTACK_ETH + PROSTACK_IP;

        pro_ptr = (uint8_t*)ipv4_hdr + offsetof(struct rte_ipv4_hdr, time_to_live);
        memcpy(&(v4_pkt->flow_key), pro_ptr, sizeof(union v4_flow_key));
        order_trans_ports(&v4_pkt->flow_key, true);

    } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
        // IPv6 TODO.
        ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *,
            sizeof(struct rte_ether_hdr));
    } else {
        printf("invalid IP packet.\n");
    }
    
    // Handle TCP and UDP
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    if (v4_pkt && v4_pkt->proto_val == TCP_PROTOCOL_NUM) {
        tcp_hdr = (struct rte_tcp_hdr*)((uint8_t*)ipv4_hdr + v4_pkt->ip_hdr_len);
        v4_pkt->is_valid_flow_key = true;
        v4_pkt->trans_hdr_len = sizeof(struct rte_tcp_hdr);
        v4_pkt->tcp_len = pkt->pkt_len - sizeof(struct rte_tcp_hdr) - 
            sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr);
        v4_pkt->tcp_ack = tcp_hdr->recv_ack;
        v4_pkt->tcp_flags = tcp_hdr->tcp_flags;
        v4_pkt->tcp_win = tcp_hdr->rx_win;
        v4_pkt->protocols_stack += PROSTACK_TCP;
        v4_pkt->highest_layer = PROSTACK_TCP;
    }
    if (v6_pkt && v6_pkt->proto_val == TCP_PROTOCOL_NUM) {

    }
    if (v4_pkt && v4_pkt->proto_val == UDP_PROTOCOL_NUM) {
        udp_hdr = (struct rte_udp_hdr*)((uint8_t*)ipv4_hdr + v4_pkt->ip_hdr_len);
        v4_pkt->is_valid_flow_key = true;
        v4_pkt->trans_hdr_len = sizeof(struct rte_udp_hdr);
        v4_pkt->udp_len = pkt->pkt_len - sizeof(struct rte_udp_hdr) - 
            sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr);
        v4_pkt->protocols_stack += PROSTACK_UDP;
        v4_pkt->highest_layer = PROSTACK_UDP;
        
    }
    if (v6_pkt && v6_pkt->proto_val == UDP_PROTOCOL_NUM) {

    }

    // Handle ICMP
    // TODO

    // Handle higher layer
    if (v4_pkt && v4_pkt->is_valid_flow_key && v4_pkt->flow_key.port_dst == 443) {
        v4_pkt->protocols_stack += PROSTACK_SSL;
        v4_pkt->highest_layer = PROSTACK_SSL;
    }
    if (v4_pkt && v4_pkt->is_valid_flow_key && v4_pkt->flow_key.port_dst == 80) {
        v4_pkt->protocols_stack += PROSTACK_HTTP;
        v4_pkt->highest_layer = PROSTACK_HTTP;
    }

    if (v4_pkt)
        print_v4_packet_info(v4_pkt);
    else if (v6_pkt)
        print_v6_packet_info(v6_pkt);

    return;
}

/**
int extract_ip_layer(const u_char* pkt_data, int ip_ver, struct packet_info* pkt_info) {
    int ret = 0;
    if (ip_ver == ETHERTYPE_IP) {
        struct iphdr* ip_header = (struct iphdr*)pkt_data;
        pkt_info->ip_hdr_len = ip_header->ihl << 2;
        pkt_info->ip_payload_length = ntohs(ip_header->tot_len) - pkt_info->ip_hdr_len;

        in_addr addr;
        addr.s_addr = ip_header->saddr;
        inet_ntop(AF_INET, &addr, pkt_info->src_ip, 16);
        addr.s_addr = ip_header->daddr;
        inet_ntop(AF_INET, &addr, pkt_info->dst_ip, 16);

        pkt_info->proto_val = ip_header->protocol;
        pkt_info->flags = ip_header->frag_off;
    } else if (ip_ver == ETHERTYPE_IPV6) {
        struct ipv6hdr* ip6_header = (struct ipv6hdr*)pkt_data;
        pkt_info->ip_hdr_len = 40;
        pkt_info->ip_payload_length = ip6_header->payload_len;
        inet_ntop(AF_INET6, &(ip6_header->saddr), pkt_info->src_ip, sizeof(pkt_info->src_ip));
        inet_ntop(AF_INET6, &(ip6_header->daddr), pkt_info->dst_ip, sizeof(pkt_info->dst_ip));

        pkt_info->proto_val = ip6_header->nexthdr;
        pkt_info->flags = 0;
    } else 
        ret = -1;
    return ret;
}

int extract_transmission_layer(const u_char* pkt_data, int trans_type, struct packet_info* pkt_info) {
    int ret = 0;

    if (trans_type == IPPROTO_TCP) {
        strncpy(pkt_info->proto_type, "tcp\0", 4);
        struct tcphdr* tcp_header = (struct tcphdr*)pkt_data;
        pkt_info->src_port = ntohs(tcp_header->source);
        pkt_info->dst_port = ntohs(tcp_header->dest);
        pkt_info->trans_hdr_len = tcp_header->doff;

        u_char flags_val = *(pkt_data + 13);
        pkt_info->tcp_flags = (flags_val & 0x3F);
        pkt_info->tcp_win = ntohs(tcp_header->window);
        pkt_info->tcp_ack = tcp_header->ack_seq;

    } else if (trans_type == IPPROTO_UDP) {
        strncpy(pkt_info->proto_type, "udp\0", 4);
        struct udphdr* udp_header = (struct udphdr*)pkt_data;
        pkt_info->src_port = ntohs(udp_header->source);
        pkt_info->dst_port = ntohs(udp_header->dest);
        pkt_info->trans_hdr_len = 8;
    }
    else {
        ret = -1;
    }
    return ret;
}

void print_packet_info(struct packet_info* pkt_info) {
    printf("\n======five tuple:========\n");
    printf("src ip: %s, dst ip: %s\n", pkt_info->src_ip, pkt_info->dst_ip);
    printf("src port: %d, dst port: %d, proto: %s\n", pkt_info->src_port, 
        pkt_info->dst_port, pkt_info->proto_type);
    printf("======ip layer:==========\n");
    printf("ip head length: %d, ip payload length: %d\n", pkt_info->ip_hdr_len, 
        pkt_info->ip_payload_length);
}

struct packet_info* alloc_packet_info() {
    struct packet_info* ret = (struct packet_info*)malloc(sizeof(struct packet_info));
    if (ret == NULL)
        return NULL;
    memset(ret, 0, sizeof(struct packet_info));
    return ret;
}

void free_packet_info(struct packet_info* ptr) {
    free(ptr);
    ptr = NULL;
}
*/
