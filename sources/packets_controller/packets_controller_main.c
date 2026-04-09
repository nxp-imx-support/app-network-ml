/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: packets_controller_main.c
 * Brief: Main entry point for packets_controller
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "common/common.h"
#include "ipc/tlv_protocol.h"
#include "ipc/socket_manager.h"
#include "xdp/xdp_controller.h"

#define DEFAULT_SOCKET_PATH "/tmp/imx_ddb.socket"
#define DEFAULT_WHITELIST_PATH "whitelist.txt"
#define MAX_WHITELIST_IPS 256
#define MAX_INTERFACES 2

// #define DEBUG_PKT

typedef struct {
    const char *ifnames[MAX_INTERFACES];
    int ifcount;
    const char *monitor_ifname;
    const char *prog_file;
    const char *socket_path;
    const char *whitelist_path;
} cli_args_t;

static uint32_t whitelist_ips[MAX_WHITELIST_IPS];
static int whitelist_count = 0;
static volatile int quit = 0;

static void signal_handler(int sig);
static void print_usage(const char *prog);
static void print_detection_result(const detection_result_t *result);
static int parse_arguments(int argc, char **argv, cli_args_t *args);
static int load_whitelist_from_config(const char *path);

#ifdef DEBUG_PKT
static void print_packet_feature(const packet_feature_t *feat);
#endif

static int recv_pkt_cnt = 0;
static int sent_pkt_cnt = 0;
static int detection_cnt = 0;

int main(int argc, char **argv)
{
    cli_args_t args = {
        .ifnames = {NULL, NULL},
        .ifcount = 0,
        .monitor_ifname = NULL,
        .prog_file = NULL,
        .socket_path = DEFAULT_SOCKET_PATH,
        .whitelist_path = DEFAULT_WHITELIST_PATH
    };

    if (parse_arguments(argc, argv, &args) != 0) {
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (xdp_init(args.ifnames, args.ifcount, args.monitor_ifname, args.prog_file) < 0) {
        fprintf(stderr, "Failed to initialize XDP\n");
        return 1;
    }

    whitelist_count = load_whitelist_from_config(args.whitelist_path);

    int server_fd = create_unix_socket_server(args.socket_path);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create socket server\n");
        xdp_cleanup();
        return 1;
    }
    fprintf(stderr, "Socket server created on %s\n", args.socket_path);

    fprintf(stderr, "Waiting for ml_detector client (Press Ctrl+C to exit)...\n");
    int client_fd;
    while (!quit) {
        client_fd = accept_client(server_fd);
        if (client_fd == -2) {
            continue;
        }
        if (client_fd < 0) {
            fprintf(stderr, "Failed to accept client\n");
            close(server_fd);
            unlink(args.socket_path);
            xdp_cleanup();
            return 1;
        }
        break;
    }

    if (quit) {
        fprintf(stderr, "\nExiting due to signal...\n");
        close(server_fd);
        unlink(args.socket_path);
        xdp_cleanup();
        return 130;
    }
    fprintf(stderr, "ml_detector client connected!\n\n");

    // main loop
    while (!quit) {
        packet_feature_t feat;

        if (xdp_read_packet_feature(&feat) < 0) {
            usleep(1000);
            continue;
        }
        recv_pkt_cnt++;

        #ifdef DEBUG_PKT
        print_packet_feature(&feat);
        #endif

        if (send_packet_feature(client_fd, &feat) < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "Failed to send packet feature\n");
            break;
        }
        detection_cnt++;
        // printf("recv pkt: %d, detection: %d\n", recv_pkt_cnt, detection_cnt);

        uint8_t result_buffer[MAX_DETECTION_RESULT_SIZE];
        detection_result_t *result_ptr = (detection_result_t *)result_buffer;
        
        if (recv_detection_result(client_fd, result_ptr) < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "Failed to receive detection result\n");
            break;
        }
        if (result_ptr->ret_size > 0)
            print_detection_result(result_ptr);

        result_entry_t *entries = (result_entry_t *)(result_buffer + sizeof(uint32_t));
        for (uint32_t i = 0; i < result_ptr->ret_size; i++) {
            if (entries[i].is_attack) {
                xdp_update_blacklist(entries[i].src_ip);
            }
        }

    }

    fprintf(stderr, "\nShutting down...\n");
    close(client_fd);
    close(server_fd);
    unlink(args.socket_path);
    xdp_cleanup();

    return 0;
}

static void signal_handler(int sig)
{
    (void)sig;
    quit = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <interface> [<interface>] -m <monitor_interface> -p <xdp_prog.o> [-s <socket_path>] [-w <whitelist_file>]\n", prog);
    fprintf(stderr, "  -i  Network interface(s) (1 or 2 interfaces, e.g., eth0 or eth0 eth1)\n");
    fprintf(stderr, "  -m  Monitor interface for ML detection (must be one of -i interfaces)\n");
    fprintf(stderr, "  -p  XDP program file (.o) (required)\n");
    fprintf(stderr, "  -s  Socket path for ml_detector IPC (optional, default: %s)\n", DEFAULT_SOCKET_PATH);
    fprintf(stderr, "  -w  Whitelist file (optional, default: %s)\n", DEFAULT_WHITELIST_PATH);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i eth0 -m eth0 -p xdp_forward_kern.o          # Single interface (echo + ML)\n", prog);
    fprintf(stderr, "  %s -i eth0 eth1 -m eth0 -p xdp_forward_kern.o    # Dual interface (eth0: ML, eth1: forward)\n", prog);
}

static void print_detection_result(const detection_result_t *result)
{
    printf("  ret_size:   %u\n", result->ret_size);
    for (uint32_t i = 0; i < result->ret_size; i++) {
        const result_entry_t *entry = &result->entries[i];
        printf("  entry[%u]: protocol=%u src_ip=%u.%u.%u.%u:%u -> dst_ip=%u.%u.%u.%u:%u is_attack=%u confidence=%u\n",
               i,
               entry->protocol,
               (entry->src_ip >> 0) & 0xFF, (entry->src_ip >> 8) & 0xFF,
               (entry->src_ip >> 16) & 0xFF, (entry->src_ip >> 24) & 0xFF,
               entry->src_port,
               (entry->dst_ip >> 0) & 0xFF, (entry->dst_ip >> 8) & 0xFF,
               (entry->dst_ip >> 16) & 0xFF, (entry->dst_ip >> 24) & 0xFF,
               entry->dst_port,
               entry->is_attack,
               entry->confidence);
    }
}

static int parse_arguments(int argc, char **argv, cli_args_t *args)
{
    int opt;
    int ifidx = 0;
    int got_monitor = 0;

    while ((opt = getopt(argc, argv, "i:m:p:s:w:h")) != -1) {
        switch (opt) {
            case 'i':
                args->ifnames[ifidx++] = optarg;
                while (optind < argc && argv[optind][0] != '-' && ifidx < MAX_INTERFACES) {
                    args->ifnames[ifidx++] = argv[optind++];
                }
                break;
            case 'm':
                args->monitor_ifname = optarg;
                got_monitor = 1;
                break;
            case 'p':
                args->prog_file = optarg;
                break;
            case 's':
                args->socket_path = optarg;
                break;
            case 'w':
                args->whitelist_path = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (ifidx == 0) {
        fprintf(stderr, "Error: At least one interface required (-i)\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!got_monitor && ifidx == 1) {
        args->monitor_ifname = args->ifnames[0];
    } else if (!got_monitor) {
        fprintf(stderr, "Error: -m required when using 2 interfaces\n");
        print_usage(argv[0]);
        return 1;
    }

    args->ifcount = ifidx;

    if (!args->prog_file) {
        fprintf(stderr, "Error: XDP program file required (-p)\n");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

static int load_whitelist_from_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }

    char line[64];
    int count = 0;
    char *ptr;

    while (fgets(line, sizeof(line), f) && count < MAX_WHITELIST_IPS) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        ptr = line;
        while (*ptr == ' ' || *ptr == '\t') {
            ptr++;
        }

        if (*ptr == '\n' || *ptr == '\0') {
            continue;
        }

        uint32_t ip;
        if (inet_pton(AF_INET, ptr, &ip) == 1) {
            whitelist_ips[count++] = ip;
        }
    }

    fclose(f);
    return count;
}

#ifdef DEBUG_PKT
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
    printf("  l3_type:     %u\n", feat->l3_type);
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
#endif