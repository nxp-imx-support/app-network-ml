/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: test_xdp_controller.c
 * Brief: XDP controller unit test
 *
 * TEST SETUP
 * ==========
 *
 * This test requires running on ARM board with XDP program loaded:
 *
 * Terminal 1 (ARM board):
 *   $ cd sources/packets_controller/unit_test
 *   $ make
 *   $ ./test_xdp_controller -i eth0 -m eth0 -p ../xdp/xdp_forward_kern.o
 *   $ ./test_xdp_controller -i eth0 eth1 -m eth0 -p ../xdp/xdp_forward_kern.o
 *
 * The test will:
 * 1. Initialize XDP with the provided interface(s) and BPF program
 * 2. Load predefined whitelist and blacklist entries into BPF maps
 * 3. Read packet features from ringbuf and display them
 *
 * Exit: Press Ctrl+C to terminate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include "../common/common.h"
#include "../ipc/socket_manager.h"
#include "../xdp/xdp_controller.h"

#define DEFAULT_IFNAME "eth0"
#define DEFAULT_PROG_FILE "xdp_forward_kern.o"
#define MAX_INTERFACES 2

static volatile int quit = 0;

static void signal_handler(int sig)
{
    (void)sig;
    quit = 1;
}

static void print_packet_feature(const packet_feature_t *feat)
{
    printf("=== Packet Feature ===\n");
    printf("  timestamp:   %lu\n", (unsigned long)feat->timestamp);
    printf("  src_mac:     %02x:%02x:%02x:%02x:%02x:%02x\n",
           feat->src_mac[0], feat->src_mac[1], feat->src_mac[2],
           feat->src_mac[3], feat->src_mac[4], feat->src_mac[5]);
    printf("  dst_mac:     %02x:%02x:%02x:%02x:%02x:%02x\n",
           feat->dst_mac[0], feat->dst_mac[1], feat->dst_mac[2],
           feat->dst_mac[3], feat->dst_mac[4], feat->dst_mac[5]);
    printf("  l3_type:     0x%04x\n", feat->l3_type);
    printf("  l2_length:   %u\n", feat->l2_length);
    printf("  src_ip:      %u.%u.%u.%u\n",
           (feat->src_ip >> 0) & 0xFF,
           (feat->src_ip >> 8) & 0xFF,
           (feat->src_ip >> 16) & 0xFF,
           (feat->src_ip >> 24) & 0xFF);
    printf("  dst_ip:      %u.%u.%u.%u\n",
           (feat->dst_ip >> 0) & 0xFF,
           (feat->dst_ip >> 8) & 0xFF,
           (feat->dst_ip >> 16) & 0xFF,
           (feat->dst_ip >> 24) & 0xFF);
    printf("  ip_flags:    0x%02x\n", feat->ip_flags);
    printf("  l4_type:     %u (6=TCP, 17=UDP, 1=ICMP)\n", feat->l4_type);
    printf("  l3_length:   %u\n", feat->l3_length);
    printf("  src_port:    %u\n", feat->src_port);
    printf("  dst_port:    %u\n", feat->dst_port);
    printf("  tcp_flags:   0x%02x\n", feat->tcp_flags);
    printf("  tcp_ack:     %u\n", (unsigned int)feat->tcp_ack);
    printf("  tcp_win:     %u\n", feat->tcp_win);
    printf("  icmp_type:   %u\n", feat->icmp_type);
    printf("  l4_length:   %u\n", feat->l4_length);
    printf("  pad:         %02x %02x %02x %02x %02x %02x %02x\n",
           feat->pad[0], feat->pad[1], feat->pad[2], feat->pad[3],
           feat->pad[4], feat->pad[5], feat->pad[6]);
    printf("\n");
}

static void print_flow_rule(const char *label, const flow_rule_t *rule)
{
    char src_ip_str[16];
    char dst_ip_str[16];

    inet_ntop(AF_INET, &rule->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &rule->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    printf("  %s: protocol=%u src_ip=%s:%u -> dst_ip=%s:%u\n",
           label,
           rule->protocol,
           src_ip_str, ntohs(rule->src_port),
           dst_ip_str, ntohs(rule->dst_port));
}

static int test_whitelist_update(void)
{
    printf("\n=== Loading Whitelist Entries ===\n");

    uint32_t whitelist[] = {
        inet_addr("127.0.0.1"), inet_addr("10.0.0.1")
    };
    int num_entries = (int)(sizeof(whitelist) / sizeof(whitelist[0]));

    for (int i = 0; i < num_entries; i++) {
        if (xdp_update_whitelist(whitelist[i]) < 0) {
            fprintf(stderr, "Failed to update whitelist[%d]\n", i);
            return -1;
        }
    }

    printf("Whitelist loaded: %d entries\n", num_entries);
    return 0;
}

static int test_blacklist_update(void)
{
    printf("\n=== Loading Blacklist Entries ===\n");

    flow_rule_t blacklist[] = {
        {6,  inet_addr("1.2.3.4"),   0,      0,      0},
        {17, inet_addr("5.6.7.8"),   0,      0,      htons(53)},
    };
    int num_entries = (int)(sizeof(blacklist) / sizeof(blacklist[0]));

    for (int i = 0; i < num_entries; i++) {
        print_flow_rule("Adding", &blacklist[i]);
        if (xdp_update_blacklist(&blacklist[i]) < 0) {
            fprintf(stderr, "Failed to update blacklist[%d]\n", i);
            return -1;
        }
    }

    printf("Blacklist loaded: %d entries\n", num_entries);
    return 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <interface> [<interface>] -m <monitor_interface> -p <xdp_prog.o>\n", prog);
    fprintf(stderr, "  -i  Network interface(s) (1 or 2 interfaces, e.g., eth0 or eth0 eth1)\n");
    fprintf(stderr, "  -m  Monitor interface for ML detection (must be one of -i interfaces)\n");
    fprintf(stderr, "  -p  XDP program file (.o) (default: %s)\n", DEFAULT_PROG_FILE);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i eth0 -m eth0 -p xdp_forward_kern.o          # Single interface (echo + ML)\n", prog);
    fprintf(stderr, "  %s -i eth0 eth1 -m eth0 -p xdp_forward_kern.o    # Dual interface (eth0: ML, eth1: forward)\n", prog);
}

int main(int argc, char **argv)
{
    const char *ifnames[MAX_INTERFACES] = {NULL, NULL};
    int ifcount = 0;
    const char *monitor_ifname = NULL;
    const char *prog_file = DEFAULT_PROG_FILE;
    int opt;
    int ifidx = 0;
    int got_monitor = 0;

    while ((opt = getopt(argc, argv, "i:m:p:h")) != -1) {
        printf("Processing option: -%c, optind = %d\n", opt, optind);
        switch (opt) {
            case 'i':
                printf("Add interface: %s\n", optarg);
                ifnames[ifidx++] = optarg;
                printf(" optind = %d, argc = %d, argv = %s\n", optind, argc, argv[optind]);
                while (optind < argc && argv[optind][0] != '-' && ifidx < MAX_INTERFACES) {
                    printf("Add interface: %s\n", argv[optind]);
                    ifnames[ifidx++] = argv[optind++];
                }
                break;
            case 'm':
                monitor_ifname = optarg;
                got_monitor = 1;
                break;
            case 'p':
                prog_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    if (ifidx == 0) {
        fprintf(stderr, "Error: At least one interface required (-i)\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!got_monitor && ifidx == 1) {
        monitor_ifname = ifnames[0];
    } else if (!got_monitor) {
        fprintf(stderr, "Error: -m required when using 2 interfaces\n");
        print_usage(argv[0]);
        return 1;
    }

    ifcount = ifidx;

    printf("XDP Controller Unit Test\n");
    printf("========================\n");
    printf("Interface(s):  ");
    for (int i = 0; i < ifcount; i++) {
        printf("%s ", ifnames[i]);
    }
    printf("\n");
    printf("Monitor:       %s\n", monitor_ifname);
    printf("XDP Program:   %s\n", prog_file);
    printf("\n");
    printf("Press Ctrl+C to exit\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (xdp_init(ifnames, ifcount, monitor_ifname, prog_file) < 0) {
        fprintf(stderr, "Failed to initialize XDP\n");
        return 1;
    }
    printf("XDP initialized successfully\n");

    if (test_whitelist_update() < 0) {
        xdp_cleanup();
        return 1;
    }

    if (test_blacklist_update() < 0) {
        xdp_cleanup();
        return 1;
    }

    printf("\n=== Reading Packet Features from Ringbuf ===\n");
    printf("(Waiting for packets to arrive on monitor interface...)\n\n");

    int count = 0;
    while (!quit) {
        packet_feature_t feat;

        int status = xdp_read_packet_feature(&feat);
        if (status == 0) {
            count++;
            printf("[%d] ", count);
            print_packet_feature(&feat);
        } else if (status == -1) 
            fprintf(stderr, "Error reading packet feature: ring buffer poll error\n");

        // sleep 100ms for test
        usleep(1000 * 100);
    }

    printf("\nShutting down...\n");
    xdp_cleanup();
    printf("XDP cleaned up\n");
    printf("Total packets received: %d\n", count);

    return 0;
}