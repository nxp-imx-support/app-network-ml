#include <vector>
#include <stdint.h>
#include <sys/types.h>

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

const int LOG_LEVEL_DEBUG = LOG_LEVEL_DEBUG_3;
const int G_LOG_LEVEL = (LOG_LEVEL_DEBUG | LOG_LEVEL_ERROR);

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

// Descript the shape of array.
struct array_desc {
    uint64_t row;
    uint64_t col;
};

void print_bytes_hex(const char* buf, size_t len);

void print_log(int log_level, const char* file_name, unsigned int line, const char* func_name, const char* tag, const char* fmt, ...);

char* pack_double_type_array(struct array_desc arr_desc, size_t rows, std::vector<pktFeaturePtr>& arr);

int unpack_double_type_array(char* buf, ssize_t buf_length, std::vector<double>& arr);