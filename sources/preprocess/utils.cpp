/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "utils.h"
#include <fstream>
#include <iostream>
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <arpa/inet.h>


int G_LOG_LEVEL;

void print_log(int log_level, const char* file_name, unsigned int line, 
               const char* func_name, const char* tag, const char* fmt, ...) {
    if ((log_level & G_LOG_LEVEL) == 0)
        return;
    if ((log_level & LOG_LEVEL_INFO) || (log_level & LOG_LEVEL_ERROR))
        printf("[%s] ", tag);
    else
        printf("[%s] In %s:%u:%s, ", tag, file_name, line, func_name);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

void print_bytes_hex(const char* buf, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
    return;
}

/**
 * Pack 2D features array
*/
char* pack_double_type_array(struct array_desc arr_desc, size_t rows, std::vector<pktFeaturePtr>& arr) {
    char* ret_buf = (char*)malloc(arr_desc.row * arr_desc.col * sizeof(double));
    if (ret_buf == NULL) {
        LOG_ERROR("malloc error.\n");
        return NULL;
    }
    int offset = 0;
    size_t copy_length = rows * arr_desc.col * sizeof(double);
    for (auto it = arr.begin(); it != arr.end(); ++it) {
        memcpy(ret_buf + offset, *it, copy_length);
        offset += copy_length;
    }
    return ret_buf;
}

/**
 * Unpack 1D inference result array
*/
int unpack_double_type_array(char* buf, ssize_t buf_length, std::vector<double>& arr) {
    LOG_DEBUG("In unpack_double_type_array.\n");
    double* d_ptr = (double*)buf;
    ssize_t arr_length = buf_length / sizeof(double);
    std::copy(d_ptr, d_ptr + arr_length, std::back_inserter(arr));
    // for (auto it = arr.begin(); it != arr.end(); ++it) {
    //     LOG_DEBUG("%lf ", *it);
    // }
    return 0;
}

int parse_configuration(const std::string config_path, configuration_items& cfgs) {
    std::ifstream cfg_json_file(config_path);
    if (!cfg_json_file.is_open()) {
        printf("Open '%s' failed.\n", config_path.c_str());
        return -1;
    }
    nlohmann::json json_cfgs;
    cfg_json_file >> json_cfgs;
    // Get report file path
    cfgs.report_json_path = json_cfgs["report_json_path"];

    // Get log level
    std::string log_level_str = json_cfgs["log_level"];
    if (log_level_str == "info")
        G_LOG_LEVEL = LOG_LEVEL_ERROR | LOG_LEVEL_INFO;
    else if (log_level_str == "debug_0")
        G_LOG_LEVEL = LOG_LEVEL_ERROR | LOG_LEVEL_INFO | LOG_LEVEL_DEBUG_0;
    else if (log_level_str == "debug_1")
        G_LOG_LEVEL = LOG_LEVEL_ERROR | LOG_LEVEL_INFO | LOG_LEVEL_DEBUG_1;
    else if (log_level_str == "debug_2")
        G_LOG_LEVEL = LOG_LEVEL_ERROR | LOG_LEVEL_INFO | LOG_LEVEL_DEBUG_2;
    else if (log_level_str == "debug_3")
        G_LOG_LEVEL = LOG_LEVEL_ERROR | LOG_LEVEL_INFO | LOG_LEVEL_DEBUG_3;
    else if (log_level_str == "error")
        G_LOG_LEVEL = LOG_LEVEL_ERROR;
    else {
        printf("Invalid log_level confgiuration: %s\n", log_level_str);
        return -1;
    }

    // Get share memory key
    char* endptr = NULL;
    std::string hex_string = json_cfgs["share_mem_key"];
    cfgs.share_mem_key = strtol(hex_string.c_str(), &endptr, 16);

    // Get white IP list
    uint32_t ip_buf;
    int status = 0;
    std::vector<std::string> ip_list = json_cfgs["white_ip_list"];
    for (auto it : ip_list) {
        status = inet_pton(AF_INET, it.c_str(), &ip_buf);
        if (status < 0) {
            printf("Convert %s to IPv4 error.\n", it);
            return -1;
        }
        cfgs.ip_white_set.insert(ip_buf);
        LOG_DEBUG("Add to IP white list: %x\n", ip_buf);
    }
    
    return 0;
}

/**
 * Export report log to json file
 */
void export_report(const std::string report_json_path, l2capfwd_report* report_ptr) {
    nlohmann::json json_log;
    json_log["cur_packets_rx"] = report_ptr->cur_packets_rx;
    json_log["cur_packets_tx"] = report_ptr->cur_packets_tx;
    json_log["previous_packets_rx"] = report_ptr->previous_packets_rx;
    json_log["previous_packets_tx"] = report_ptr->previous_packets_tx;
    json_log["ddos_cnt"] = report_ptr->ddos_cnt;
    json_log["total_cnt"] = report_ptr->total_cnt;
    json_log["time_period"] = report_ptr->time_period;
    json_log["ip_info_list"] = nlohmann::json::array();
    for (auto it : report_ptr->ip_info_list) {
        json_log["ip_info_list"].push_back(it);
    }
    std::ofstream o_file(report_json_path);
    if (!o_file) {
        LOG_ERROR("Open l2capfwd report file failed!");
        return;
    }
    o_file << json_log << std::endl;
    o_file.close();
}