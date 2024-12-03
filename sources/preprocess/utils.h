#ifndef _L2CAPFWD_UTILS_HDR
#define _L2CAPFWD_UTILS_HDR
#include <vector>
#include <stdint.h>
#include <sys/types.h>
#include <string>
#include <fstream>
#include <unordered_set>
#include "nlohmann/json.hpp"

typedef double(*pktFeaturePtr)[11];

/**
 * Log level
*/
const int LOG_LEVEL_INFO = 1;
const int LOG_LEVEL_DEBUG_0 = 2;
const int LOG_LEVEL_DEBUG_1 = 4;
const int LOG_LEVEL_DEBUG_2 = 8;
const int LOG_LEVEL_DEBUG_3 = 16;
const int LOG_LEVEL_ERROR = 128;

#define LOG_INFO(fmt, ...) \
    print_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "INFO", fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    print_log(LOG_LEVEL_DEBUG_0, __FILE__, __LINE__, __func__, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_DEBUG_1(fmt, ...) \
    print_log(LOG_LEVEL_DEBUG_1, __FILE__, __LINE__, __func__, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_DEBUG_2(fmt, ...) \
    print_log(LOG_LEVEL_DEBUG_2, __FILE__, __LINE__, __func__, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_DEBUG_3(fmt, ...) \
    print_log(LOG_LEVEL_DEBUG_3, __FILE__, __LINE__, __func__, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    print_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ERROR", fmt, ##__VA_ARGS__)

class l2capfwd_report {
public:
    uint64_t cur_packets_rx;
    uint64_t cur_packets_tx;
    uint64_t previous_packets_rx;
    uint64_t previous_packets_tx;
    int time_period;
    uint64_t ddos_cnt;
    uint64_t total_cnt;
    std::vector<std::string> ip_info_list;

    l2capfwd_report() : cur_packets_rx(0), cur_packets_tx(0), 
                        previous_packets_rx(0), previous_packets_tx(0), 
                        ip_info_list(), time_period(0), ddos_cnt(0), total_cnt(0) {}
};

#define CONFIGRATION_FILE "./config.json"

class configuration_items {
public:
    std::string report_json_path;
    int share_mem_key;
    int log_level;
    std::unordered_set<uint32_t> ip_white_set;

    configuration_items() : share_mem_key(0), log_level(1) {}
};

// Descript the shape of array.
struct array_desc {
    uint64_t row;
    uint64_t col;
};

void print_bytes_hex(const char* buf, size_t len);

void print_log(int log_level, const char* file_name, unsigned int line, const char* func_name, const char* tag, const char* fmt, ...);

char* pack_double_type_array(struct array_desc arr_desc, size_t rows, std::vector<pktFeaturePtr>& arr);

int unpack_double_type_array(char* buf, ssize_t buf_length, std::vector<double>& arr);

int parse_configuration(const std::string config_path, configuration_items& cfgs);
void export_report(const std::string report_json_path, l2capfwd_report* report_ptr);
#endif