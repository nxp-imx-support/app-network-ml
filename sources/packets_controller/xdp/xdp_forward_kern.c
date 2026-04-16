/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_forward_kern.c
 * Brief: XDP kernel program for packet forwarding and filtering
 * 
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>
#include "common.h"
#include "xdp_kern.h"

static __always_inline void stats_increment(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline int match_whitelist_flow(__u32 src_ip, __u32 dst_ip)
{
    if (bpf_map_lookup_elem(&whitelist_map, &src_ip)) 
        return 1;
    if (bpf_map_lookup_elem(&whitelist_map, &dst_ip))
        return 1;

    return 0;
}

static __always_inline int match_blacklist_flow(__u32 src_ip)
{
    __u32 *val = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    return val && *val == 1;
}

SEC("xdp")
int xdp_forward_prog(struct xdp_md *ctx)
{
    stats_increment(STATS_IDX_RX);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u16 tcp_flags = 0;
    __u8 icmp_type = 0;
    __u32 tcp_ack_seq = 0;
    __u32 tcp_win = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            stats_increment(STATS_IDX_PASS);
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        __u8 flags_byte = ((__u8 *)tcp)[13];
        tcp_ack_seq = tcp->ack_seq;
        tcp_win = bpf_ntohs(tcp->window);
        tcp_flags = 0x3F & flags_byte;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            stats_increment(STATS_IDX_PASS);
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
        if ((void *)(icmp + 1) > data_end) {
            stats_increment(STATS_IDX_PASS);
            return XDP_PASS;
        }
        icmp_type = icmp->type;
    } else {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    for (__u32 i = 0; i < sizeof(pass_ports) / sizeof(pass_ports[0]); i++) {
        if (dst_port == pass_ports[i] || src_port == pass_ports[i]) {
            stats_increment(STATS_IDX_PASS);
            return XDP_PASS;
        }
    }

    if (match_whitelist_flow(ip->saddr, ip->daddr)) {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    if (match_blacklist_flow(ip->saddr)) {
        stats_increment(STATS_IDX_DROP);
        return XDP_DROP;
    }

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    __u32 *is_monitor = bpf_map_lookup_elem(&monitor_ifindex_map, &ingress_ifindex);
    if (is_monitor && *is_monitor == 1) {
        packet_feature_t *pkt = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(packet_feature_t), 0);
        if (pkt) {
            stats_increment(STATS_IDX_SUBMIT);
            __builtin_memset(pkt, 0, sizeof(packet_feature_t));
            pkt->timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(pkt->src_mac, eth->h_source, MAC_ADDRESS_LENGTH);
            __builtin_memcpy(pkt->dst_mac, eth->h_dest, MAC_ADDRESS_LENGTH);
            pkt->l3_type = bpf_ntohs(eth->h_proto);
            pkt->l2_length = ctx->data_end - ctx->data;
            pkt->src_ip = ip->saddr;
            pkt->dst_ip = ip->daddr;
            pkt->ip_flags = (bpf_ntohs(ip->frag_off) >> 13);
            pkt->l4_type = ip->protocol;
            pkt->l3_length = bpf_ntohs(ip->tot_len);
            pkt->src_port = src_port;
            pkt->dst_port = dst_port;
            pkt->tcp_flags = tcp_flags;
            pkt->tcp_ack = tcp_ack_seq;
            pkt->tcp_win = tcp_win;
            pkt->icmp_type = icmp_type;
            pkt->l4_length = pkt->l3_length - (ip->ihl * 4);
            bpf_ringbuf_submit(pkt, 0);
        }
    }

    __u32 idx = 0;
    __u32 *ifcount_ptr = bpf_map_lookup_elem(&ifindex_map, &idx);
    if (!ifcount_ptr) {
        stats_increment(STATS_IDX_PASS);
        return XDP_PASS;
    }

    __u32 ifcount = *ifcount_ptr;

    if (ifcount == 2) {
        __u32 ifindexes[2] = {0, 0};
        idx = 1;
        __u32 *ifindex0 = bpf_map_lookup_elem(&ifindex_map, &idx);
        if (ifindex0)
            ifindexes[0] = *ifindex0;

        idx = 2;
        __u32 *ifindex1 = bpf_map_lookup_elem(&ifindex_map, &idx);
        if (ifindex1)
            ifindexes[1] = *ifindex1;

        __u32 other_ifindex = (ingress_ifindex == ifindexes[0]) ? ifindexes[1] : ifindexes[0];
        if (other_ifindex != 0)
            return bpf_redirect(other_ifindex, 0);
    }

    stats_increment(STATS_IDX_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";