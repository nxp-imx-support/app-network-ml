#include "extract_protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdlib.h>

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

