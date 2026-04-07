/* Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * File: test_ipc_integration.c
 * Brief: IPC integration test between C (packets_controller) and Python (detector_main.py)
 *
 * TEST SETUP (Manual Pairing Required)
 * =====================================
 *
 * This test requires running detector_main.py (Python) separately in another terminal:
 *
 * Terminal 1 (Python - ml_detector):
 *   $ cd sources/ml_detector/imx_board
 *   $ python3 detector_main.py --socket-path /tmp/imx_ddb.socket
 *
 * Terminal 2 (C - packets_controller):
 *   $ cd sources/packets_controller/unit_test
 *   $ make
 *   $ ./test_ipc_integration /tmp/imx_ddb.socket
 *
 * The C program acts as the server and will:
 * 1. Wait for Python client connection
 * 2. Run test cases that send packet_feature_t to Python
 * 3. Receive and display detection_result_t from Python
 *
 * Exit: Press Ctrl+C to terminate both programs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "../common/common.h"
#include "../ipc/tlv_protocol.h"
#include "../ipc/socket_manager.h"

#define SOCKET_PATH_DEFAULT "/tmp/imx_ddb.socket"

static volatile int quit = 0;

void signal_handler(int sig)
{
    (void)sig;
    quit = 1;
}

static void print_packet_feature(const packet_feature_t *feat)
{
    printf("  timestamp:  %lu\n", (unsigned long)feat->timestamp);
    printf("  src_mac:    %02x:%02x:%02x:%02x:%02x:%02x\n",
           feat->src_mac[0], feat->src_mac[1], feat->src_mac[2],
           feat->src_mac[3], feat->src_mac[4], feat->src_mac[5]);
    printf("  dst_mac:    %02x:%02x:%02x:%02x:%02x:%02x\n",
           feat->dst_mac[0], feat->dst_mac[1], feat->dst_mac[2],
           feat->dst_mac[3], feat->dst_mac[4], feat->dst_mac[5]);
    printf("  l3_type:    0x%04x\n", feat->l3_type);
    printf("  src_ip:     %u.%u.%u.%u\n",
           (feat->src_ip >> 0) & 0xFF,
           (feat->src_ip >> 8) & 0xFF,
           (feat->src_ip >> 16) & 0xFF,
           (feat->src_ip >> 24) & 0xFF);
    printf("  dst_ip:     %u.%u.%u.%u\n",
           (feat->dst_ip >> 0) & 0xFF,
           (feat->dst_ip >> 8) & 0xFF,
           (feat->dst_ip >> 16) & 0xFF,
           (feat->dst_ip >> 24) & 0xFF);
    printf("  l4_type:    %u\n", feat->l4_type);
    printf("  src_port:   %u\n", feat->src_port);
    printf("  dst_port:   %u\n", feat->dst_port);
    printf("  tcp_flags:  0x%02x\n", feat->tcp_flags);
    printf("  tcp_ack:    %u\n", (unsigned int)feat->tcp_ack);
    printf("  tcp_win:    %u\n", feat->tcp_win);
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

static int test_validate_struct_sizes(void)
{
    printf("\n=== Testing Structure Sizes ===\n");

    printf("packet_feature_t:  expected 64, actual %zu\n", sizeof(packet_feature_t));
    printf("result_entry_t:    expected 21, actual %zu\n", sizeof(result_entry_t));
    printf("tlv_header_t:      expected 6,  actual %zu\n", sizeof(tlv_header_t));

    int pass = 1;
    if (sizeof(packet_feature_t) != 64) {
        printf("FAIL: packet_feature_t size mismatch\n");
        pass = 0;
    }
    if (sizeof(result_entry_t) != 21) {
        printf("FAIL: result_entry_t size mismatch\n");
        pass = 0;
    }
    if (sizeof(tlv_header_t) != 6) {
        printf("FAIL: tlv_header_t size mismatch\n");
        pass = 0;
    }

    return pass;
}

static int test_single_packet(int client_fd)
{
    printf("\n=== Test Case 1: Single Packet ===\n");

    packet_feature_t feature = {
        .timestamp = 1234567890,
        .src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .dst_mac = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
        .l3_type = 0x0800,
        .l2_length = 64,
        .src_ip = 0xc0a8000a,
        .dst_ip = 0xc0a80001,
        .ip_flags = 0x40,
        .l4_type = 6,
        .l3_length = 40,
        .src_port = 5000,
        .dst_port = 80,
        .tcp_flags = 0x02,
        .tcp_ack = 0,
        .tcp_win = 65535,
        .icmp_type = 0,
        .l4_length = 40,
        .pad = {0}
    };

    printf("\nSending packet feature:\n");
    print_packet_feature(&feature);

    if (send_packet_feature(client_fd, &feature) < 0) {
        fprintf(stderr, "Failed to send packet feature\n");
        return -1;
    }

    detection_result_t result;
    if (recv_detection_result(client_fd, &result) < 0) {
        fprintf(stderr, "Failed to receive detection result\n");
        return -1;
    }

    printf("\nReceived detection result:\n");
    print_detection_result(&result);

    return 0;
}

static int test_multiple_packets_in_multiple_flow(int client_fd)
{
    printf("\n=== Test Case 2: Multiple Packets in Multiple Flows ===\n");

    struct flow_def {
        uint8_t l4_type;
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t dst_ip;
        uint16_t dst_port;
        int packet_count;
        const char *name;
    };

    struct flow_def flows[] = {
        {6,  0xc0a80164, 5000, 0xc0a80101, 80,  10, "TCP flow 1 (192.168.1.100:5000 -> 192.168.1.1:80)"},
        {17, 0xc0a801c8, 6000, 0xc0a80102, 53,  15, "UDP flow 1 (192.168.1.200:6000 -> 192.168.1.2:53)"},
        {6,  0x0a000032, 7000, 0x0a000001, 443, 8,  "TCP flow 2 (10.0.0.50:7000 -> 10.0.0.1:443)"},
    };
    int num_flows = (int)(sizeof(flows) / sizeof(flows[0]));
    int total_packets = 0;
    int total_results = 0;

    uint64_t base_timestamp = 9876543210ULL;

    for (int f = 0; f < num_flows && !quit; f++) {
        printf("\n--- Processing %s (%d packets) ---\n",
               flows[f].name, flows[f].packet_count);

        for (int p = 0; p < flows[f].packet_count && !quit; p++) {
            packet_feature_t feature = {
                .timestamp = base_timestamp + p,
                .src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                .dst_mac = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
                .l3_type = 0x0800,
                .l2_length = 64,
                .src_ip = flows[f].src_ip,
                .dst_ip = flows[f].dst_ip,
                .ip_flags = 0x40,
                .l4_type = flows[f].l4_type,
                .l3_length = 40,
                .src_port = flows[f].src_port,
                .dst_port = flows[f].dst_port,
                .tcp_flags = (flows[f].l4_type == 6) ? 0x02 : 0,
                .tcp_ack = (flows[f].l4_type == 6) ? (p * 1000) : 0,
                .tcp_win = 65535,
                .icmp_type = 0,
                .l4_length = 40,
                .pad = {0}
            };

            printf("\n[Flow %d, Packet %d] Sending:\n", f + 1, p + 1);
            print_packet_feature(&feature);

            if (send_packet_feature(client_fd, &feature) < 0) {
                fprintf(stderr, "Failed to send packet feature\n");
                return -1;
            }
            total_packets++;

            detection_result_t result;
            if (recv_detection_result(client_fd, &result) < 0) {
                fprintf(stderr, "Failed to receive detection result\n");
                return -1;
            }

            printf("\n[Flow %d, Packet %d] Received result:\n", f + 1, p + 1);
            print_detection_result(&result);
            total_results++;
        }
    }

    printf("\n=== Flow Test Summary ===\n");
    printf("Total packets sent:    %d\n", total_packets);
    printf("Total results received: %d\n", total_results);

    return 0;
}

int main(int argc, char **argv)
{
    const char *socket_path = SOCKET_PATH_DEFAULT;

    if (argc >= 2) {
        socket_path = argv[1];
    }

    printf("IPC Integration Test - packets_controller vs detector_main.py\n");
    printf("================================================================\n");
    printf("Socket path: %s\n", socket_path);
    printf("\n");
    printf("MANUAL SETUP REQUIRED:\n");
    printf("  1. In another terminal, run:\n");
    printf("     $ cd sources/ml_detector/imx_board\n");
    printf("     $ python3 detector_main.py --socket-path %s\n", socket_path);
    printf("  2. Then press Enter here to continue...\n");
    printf("\n");
    printf("Press Ctrl+C to exit\n\n");

    printf("Waiting for Python client to connect...\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int server_fd = create_unix_socket_server(socket_path);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create UNIX socket server: %s\n", socket_path);
        return 1;
    }
    printf("Server created on %s\n", socket_path);
    printf("Waiting for Python client to connect (Press Ctrl+C to exit)...\n");

    int client_fd;
    while (!quit) {
        client_fd = accept_client(server_fd);
        if (client_fd == -2) {
            continue;
        }
        if (client_fd < 0) {
            fprintf(stderr, "Failed to accept client\n");
            close(server_fd);
            unlink(socket_path);
            return 1;
        }
        break;
    }

    if (quit) {
        printf("\nExiting due to signal...\n");
        close(server_fd);
        unlink(socket_path);
        return 130;
    }

    printf("Client connected!\n\n");

    int ret = 0;

    if (!test_validate_struct_sizes()) {
        ret = 1;
    }

    if (ret == 0 && test_single_packet(client_fd) < 0) {
        ret = 1;
    }

    if (ret == 0 && test_multiple_packets_in_multiple_flow(client_fd) < 0) {
        ret = 1;
    }

    close(client_fd);
    close(server_fd);
    unlink(socket_path);

    printf("\nTest %s\n", ret == 0 ? "PASSED" : "FAILED");

    return ret;
}
