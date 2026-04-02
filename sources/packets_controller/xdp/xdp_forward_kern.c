/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: xdp_forward_kern.c
 * Brief: XDP kernel program for packet forwarding and filtering
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

#define MAX_FLOWS 10000
#define MAC_ADDRESS_LENGTH 6
#define PAD_BUFFER_SIZE 7

struct flow_rule {
    __u8 protocol;
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
} __attribute__((packed));

struct packet_feature {
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
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_rule);
    __type(value, __u32);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_rule);
    __type(value, __u32);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 2);
} packet_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} ifindex_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} monitor_ifindex_map SEC(".maps");

static __always_inline int match_whitelist_flow(__u32 src_ip, __u32 dst_ip)
{
    struct flow_rule key = {0};
    struct flow_rule *cur;
    __u32 ip_to_check;
    int i;

    for (i = 0; i < MAX_FLOWS; i++) {
        key.protocol = 0;
        key.src_ip = 0;
        key.dst_ip = 0;
        key.src_port = 0;
        key.dst_port = 0;

        cur = bpf_map_lookup_elem(&whitelist_map, &key);
        if (!cur)
            break;

        ip_to_check = cur->src_ip;
        if (ip_to_check != 0 && (ip_to_check == src_ip || ip_to_check == dst_ip))
            return 1;

        ip_to_check = cur->dst_ip;
        if (ip_to_check != 0 && (ip_to_check == src_ip || ip_to_check == dst_ip))
            return 1;
    }

    return 0;
}

static __always_inline int match_blacklist_exact(struct flow_rule *key)
{
    __u32 *val = bpf_map_lookup_elem(&blacklist_map, key);
    return val && *val == 1;
}

SEC("xdp")
int xdp_forward_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_rule key = {0};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    __u16 src_port = 0, dst_port = 0;
    __u16 tcp_flags = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        tcp_flags = *(unsigned char *)(tcp + 1);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    key.src_port = src_port;
    key.dst_port = dst_port;

    if (match_whitelist_flow(key.src_ip, key.dst_ip))
        return XDP_PASS;

    if (match_blacklist_exact(&key))
        return XDP_DROP;

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    __u32 *is_monitor = bpf_map_lookup_elem(&monitor_ifindex_map, &ingress_ifindex);
    if (is_monitor && *is_monitor == 1) {
        struct packet_feature *pkt = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(struct packet_feature), 0);
        if (pkt) {
            __builtin_memset(pkt, 0, sizeof(struct packet_feature));
            pkt->timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(pkt->src_mac, eth->h_source, MAC_ADDRESS_LENGTH);
            __builtin_memcpy(pkt->dst_mac, eth->h_dest, MAC_ADDRESS_LENGTH);
            pkt->l3_type = eth->h_proto;
            pkt->l2_length = ctx->data_end - ctx->data;
            pkt->src_ip = ip->saddr;
            pkt->dst_ip = ip->daddr;
            pkt->ip_flags = ip->frag_off;
            pkt->l4_type = ip->protocol;
            pkt->l3_length = ip->tot_len;
            pkt->src_port = src_port;
            pkt->dst_port = dst_port;
            pkt->tcp_flags = tcp_flags;
            pkt->tcp_ack = 0;
            pkt->tcp_win = 0;
            pkt->icmp_type = 0;
            pkt->l4_length = ip->tot_len - (ip->ihl * 4);
            bpf_ringbuf_submit(pkt, 0);
        }
    }

    __u32 idx = 0;
    __u32 *ifcount_ptr = bpf_map_lookup_elem(&ifindex_map, &idx);
    if (!ifcount_ptr)
        return XDP_PASS;

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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";