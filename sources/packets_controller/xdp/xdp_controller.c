// Copyright 2025 NXP
// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "../ipc/socket_manager.h"
#include "../ipc/tlv_protocol.h"

static volatile int quit = 0;
static int ifindex = -1;
static int prog_fd = -1;
static int flow_map_fd = -1;

void signal_handler(int sig) {
    quit = 1;
}

int load_xdp_program(const char *filename, const char *ifname) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;

    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_forward_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        bpf_object__close(obj);
        return -1;
    }

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    flow_map_fd = bpf_object__find_map_fd_by_name(obj, "flow_table");
    printf("XDP program loaded on %s\n", ifname);
    return 0;
}

void cleanup() {
    if (ifindex > 0 && prog_fd > 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        printf("XDP program detached\n");
    }
}

int main(int argc, char **argv) {
    if (argc != 6 || strcmp(argv[1], "-i") != 0 || strcmp(argv[3], "-p") != 0 || strcmp(argv[5], "-s") != 0) {
        fprintf(stderr, "Usage: %s -i <interface> -p <xdp_prog.o> -s <socket_path>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[2];
    const char *prog_file = argv[4];
    const char *socket_path = argv[6];

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (load_xdp_program(prog_file, ifname) < 0)
        return 1;

    int server_fd = create_unix_socket_server(socket_path);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create socket\n");
        cleanup();
        return 1;
    }

    printf("Waiting for Python client on %s\n", socket_path);
    int client_fd = accept_client(server_fd);
    if (client_fd < 0) {
        fprintf(stderr, "Failed to accept client\n");
        close(server_fd);
        cleanup();
        return 1;
    }
    printf("Client connected\n");

    while (!quit) {
        detection_result_t result;
        if (recv_detection_result(client_fd, &result) < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Failed to receive result\n");
            break;
        }

        if (result.is_attack) {
            // Update flow table to block this flow
            // Note: In real implementation, need to extract flow_key from result
            printf("Attack detected, confidence: %d%%\n", result.confidence);
        }
    }

    close(client_fd);
    close(server_fd);
    unlink(socket_path);
    cleanup();
    return 0;
}



