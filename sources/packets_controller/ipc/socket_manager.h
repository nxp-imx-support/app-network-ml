// Copyright 2025 NXP
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SOCKET_MANAGER_H
#define SOCKET_MANAGER_H

#include <stdint.h>
#include "../common/common.h"
#include "tlv_protocol.h"

// Socket operations
int create_unix_socket_server(const char *socket_path);
int connect_unix_socket_client(const char *socket_path);
int accept_client(int server_fd);

// TLV send/receive
int send_tlv_message(int fd, uint16_t type, const void *data, uint32_t length);
int recv_tlv_message(int fd, uint16_t *type, void *buffer, uint32_t buffer_size);

int send_packet_feature(int fd, const packet_feature_t *feature);
int recv_detection_result(int fd, detection_result_t *result);

#endif // SOCKET_MANAGER_H
