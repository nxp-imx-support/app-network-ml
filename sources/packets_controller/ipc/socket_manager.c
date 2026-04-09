// Copyright 2025 NXP
// SPDX-License-Identifier: BSD-3-Clause

#include "socket_manager.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int create_unix_socket_server(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    unlink(socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int connect_unix_socket_client(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int accept_client(int server_fd) {
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        int ret = select(server_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) {
            return -2;
        }

        return accept(server_fd, NULL, NULL);
    }
}

int send_tlv_message(int fd, uint16_t type, const void *data, uint32_t length) {
    tlv_header_t header = {.type = type, .length = length};

    if (write(fd, &header, TLV_HEADER_SIZE) != TLV_HEADER_SIZE) return -1;
    if (length > 0 && write(fd, data, length) != length) return -1;

    return 0;
}

int recv_tlv_message(int fd, uint16_t *type, void *buffer, uint32_t buffer_size) {
    tlv_header_t header;

    ssize_t n = read(fd, &header, TLV_HEADER_SIZE);
    if (n != TLV_HEADER_SIZE) return -1;

    *type = header.type;

    if (header.length > buffer_size) return -1;
    if (header.length > 0 && read(fd, buffer, header.length) != header.length) return -1;

    // printf("DEBUG recv_tlv: header=");
    // for (int i = 0; i < TLV_HEADER_SIZE; i++) {
    //     printf("%02x", ((uint8_t *)&header)[i]);
    // }
    // printf(" payload=");
    // for (uint32_t i = 0; i < header.length; i++) {
    //     printf("%02x", ((uint8_t *)buffer)[i]);
    // }
    // printf("\n");

    return header.length;
}

int send_packet_feature(int fd, const packet_feature_t *feature) {
    return send_tlv_message(fd, MSG_TYPE_PACKET_FEATURES, feature, sizeof(packet_feature_t));
}

int recv_detection_result(int fd, detection_result_t *result) {
    uint16_t type;
    uint8_t buffer[MAX_DETECTION_RESULT_SIZE];

    int len = recv_tlv_message(fd, &type, buffer, MAX_DETECTION_RESULT_SIZE);
    if (len < 0) return -1;
    if (type != MSG_TYPE_DETECTION_RESULT) return -1;

    uint32_t ret_size = 0;
    memcpy(&ret_size, buffer, sizeof(uint32_t));

    uint32_t expected_len = sizeof(uint32_t) + ret_size * sizeof(result_entry_t);
    if ((uint32_t)len != expected_len) return -1;

    memcpy(result, buffer, len);
    return 0;
}
