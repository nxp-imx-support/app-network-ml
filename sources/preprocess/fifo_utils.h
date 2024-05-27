#include <vector>

// control message define
const char CTL_DOUBLE_VECTOR_START = 0x01;
const char CTL_DOUBLE_VECTOR_END = 0x02;
const char CTL_ECHO = 0x3;

/**
 * Log level
*/
const int LOG_LEVEL_INFO = 0x1;
const int LOG_LEVEL_DEBUG = 0x2;
const int LOG_LEVEL_ERROR = 0x4;


const int G_LOG_LEVEL = (LOG_LEVEL_INFO | LOG_LEVEL_DEBUG | LOG_LEVEL_ERROR);

#define LOG_INFO(fmt, ...) \
    print_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "INFO", fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    print_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    print_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ERROR", fmt, ##__VA_ARGS__)

void print_log(int log_level, const char* file_name, unsigned int line, const char* func_name, const char* tag, const char* fmt, ...);

/**
 * Init a pipe for write data
 * @param fifo_path pipe path
*/
void init_send_fifo(const char* fifo_path);

/**
 * Send a double type vector via PIPE
 * @param fifo_path pipe path
 * @param vec double type vector to be sent
 * @retval 0: success
*/
int send_vector_double(const char* fifo_path, std::vector<double>& vec);

/**
 * Send control message
 * @param fifo_path pipe path
 * @param msg defined by fifo_utils.h, started with CTL_
 * @retval 0
*/
int send_control_msg(const char* fifo_path, char msg);

/**
 * Recv control message
*/
char recv_control_msg(const char* fifo_path);