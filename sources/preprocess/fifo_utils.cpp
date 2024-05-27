#include "fifo_utils.h"
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

void init_send_fifo(const char* fifo_path) {
    mkfifo(fifo_path, 0666);
}

int send_vector_double(const char* fifo_path, std::vector<double>& vec) {
    std::ofstream fifoStream(fifo_path);
    if (!fifoStream.is_open()) {
        std::cout << "Error opening FIFO for writeing!" << std::endl;
        return 1;
    }
    uint64_t tmp = 0;
    double item = 0.f;
    size_t size = vec.size();
    uint64_t *buf = NULL;
    buf = (uint64_t*)malloc(size * sizeof(double));
    if (!buf)
        return -1;
    for (size_t i = 0; i < size; i++) {
        item = vec[i];
        memcpy(&buf[i], &item, sizeof(double));
    }
    size = size * sizeof(double);
    fifoStream.write((char*)buf, size);
    fifoStream.close();
    if (buf)
        free(buf);
    return 0;
}

int send_control_msg(const char* fifo_path, char msg) {
    std::ofstream fifoStream(fifo_path);
    if (!fifoStream.is_open()) {
        std::cout << "Error opening FIFO for writeing!" << std::endl;
        return 1;
    }
    fifoStream << msg;
    fifoStream.close();
    return 0;
}

char recv_control_msg(const char* fifo_path) {
    std::ifstream fifoStream(fifo_path);
    if (!fifoStream.is_open()) {
        std::cout << "Error opening FIFO for reading!" << std::endl;
        return 1;
    }
    std::cout << "Prepare to recv ctl msg." << std::endl;
    char msg;
    fifoStream.read(&msg, 1);
    printf("recv ctl msg: 0x%x\n", msg);
    fifoStream.close();
    return 0;
}

void print_log(int log_level, const char* file_name, unsigned int line, 
               const char* func_name, const char* tag, const char* fmt, ...) {
    if ((log_level & G_LOG_LEVEL) == 0)
        return;
    printf("[%s] In %s:%u:%s, ", tag, file_name, line, func_name);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}