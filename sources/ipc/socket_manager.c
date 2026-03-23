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
    return accept(server_fd, NULL, NULL);
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

    return header.length;
}

int send_packet_feature(int fd, const packet_feature_t *feature) {
    return send_tlv_message(fd, MSG_TYPE_PACKET_FEATURES, feature, sizeof(packet_feature_t));
}

int recv_packet_feature(int fd, packet_feature_t *feature) {
    uint16_t type;
    int len = recv_tlv_message(fd, &type, feature, sizeof(packet_feature_t));
    return (type == MSG_TYPE_PACKET_FEATURES && len == sizeof(packet_feature_t)) ? 0 : -1;
}

int send_detection_result(int fd, const detection_result_t *result) {
    return send_tlv_message(fd, MSG_TYPE_DETECTION_RESULT, result, sizeof(detection_result_t));
}

int recv_detection_result(int fd, detection_result_t *result) {
    uint16_t type;
    int len = recv_tlv_message(fd, &type, result, sizeof(detection_result_t));
    return (type == MSG_TYPE_DETECTION_RESULT && len == sizeof(detection_result_t)) ? 0 : -1;
}
