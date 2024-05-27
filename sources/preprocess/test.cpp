#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <string>
#include <cstring>
#include "fifo_utils.h"
#include "extract_protocols.h"

int test_send_vector() {
    std::vector<double> d_arr1({3.14, 5.28, 6.29, 7.62});
    std::vector<double> d_arr2({1.22, 2.33, 3.33, 4.12});
    std::vector<std::vector<double>> vec_2d;
    vec_2d.push_back(d_arr1);
    vec_2d.push_back(d_arr2);

    const char* fifo_writer = "/tmp/dpdk_fifo";
    const char* fifo_reader = "/tmp/tfl_fifo";
    init_send_fifo(fifo_writer);
    int status = 0;
    for (auto it = vec_2d.begin(); it != vec_2d.end(); it++) {
        status = send_control_msg(fifo_writer, CTL_DOUBLE_VECTOR_START);
        if (status) {
            std::cout << "send control msg error" << std::endl;
            exit(0);
        }
        recv_control_msg(fifo_reader);
        std::cout << "prepare to send data" << std::endl;
        status = send_vector_double(fifo_writer, *it);
        if (status) {
            std::cout << "send vector error" << std::endl;
            exit(0);
        }
        recv_control_msg(fifo_reader);
    }
    send_control_msg(fifo_writer, CTL_DOUBLE_VECTOR_END);
    recv_control_msg(fifo_reader);
    return 0;
}

void test_flow_table_inference() {
    // Simulate some pakcets
    union v4_flow_key flow1;
    flow1.ip_src = 113;
    flow1.ip_dst = 118;
    flow1.port_src = 453;
    flow1.port_dst = 6543;
    flow1.proto = 1;
    LOG_DEBUG("flow1 block: %016lx %016lx\n", flow1.block[0], flow1.block[1]);
    LOG_DEBUG("ip_src: %d, ip_dst: %d, port_src: %d, port_dst: %d, proto: %d\n", 
              flow1.ip_src, flow1.ip_dst, flow1.port_src, flow1.port_dst, flow1.proto);
    union v4_flow_key flow2;
    flow2.ip_src = 132;
    flow2.ip_dst = 150;
    flow2.port_src = 880;
    flow2.port_dst = 6582;
    flow2.proto = 2;

    union v4_flow_key flow3;
    flow3.ip_src = 190;
    flow3.ip_dst = 200;
    flow3.port_src = 452;
    flow3.port_dst = 6882;
    flow3.proto = 1;

    // Flow1
    for (int i = 0; i < 30; ++i) {
        struct v4_packet_info* p1 = alloc_v4_packet_info();
        p1->ts.tv_sec = i + 1;
        p1->ts.tv_usec = 8;
        p1->flags = 445;
        p1->tcp_ack = 777;
        p1->is_valid_flow_key = true;
        memcpy(&p1->flow_key, &flow1, sizeof(flow1));
        insert_v4_flow_table(p1);
    }
    // Flow2
    for (int i = 0; i < 24; ++i) {
        struct v4_packet_info* p2 = alloc_v4_packet_info();
        p2->ts.tv_sec = 98 + i;
        p2->ts.tv_usec = 44 + i;
        p2->flags = 887;
        p2->tcp_ack = 345;
        p2->is_valid_flow_key = true;
        memcpy(&p2->flow_key, &flow2, sizeof(flow2));
        insert_v4_flow_table(p2);
    }

    // Flow3
    // for (int i = 0; i < 5; ++i) {
    //     struct v4_packet_info* p3 = alloc_v4_packet_info();
    //     memset(p3, 0x06, sizeof(struct v4_packet_info));
    //     memcpy(&p3->flow_key, &flow3, sizeof(flow3));
    //     insert_v4_flow_table(p3);
    // }
    
    print_v4_flow_table();
    flow_table_inference();
    v4_flow_table_cleanup();
    return;
}

int main() {
    test_flow_table_inference();
    return 0;
}

