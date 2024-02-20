#include "read_packets.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Invalid, argc shouble be 3" << std::endl;
        return -1;
    }
    const char* pcap_file = argv[1];
    const char* pipe_name = argv[2];
    offline_pcap_read(pcap_file, pipe_name);
    return 0;
}