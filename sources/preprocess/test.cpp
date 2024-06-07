#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <string>
#include <cstring>
#include <signal.h>
#include "utils.h"
#include "extract_protocols.h"

bool quit_flag;

void signal_handler(int signum) {
    LOG_DEBUG("Received signal, exit...\n");
    quit_flag = true;
}

void generate_flow_sample() {
    // Simulate some pakcets
    union v4_flow_key flow1;
    flow1.ip_src = 113;
    flow1.ip_dst = 118;
    flow1.port_src = 453;
    flow1.port_dst = 6543;
    flow1.proto = 1;
    LOG_DEBUG_1("flow1 block: %016lx %016lx\n", flow1.block[0], flow1.block[1]);
    LOG_DEBUG_1("ip_src: %d, ip_dst: %d, port_src: %d, port_dst: %d, proto: %d\n", 
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
        p1->packet_length = 1111;
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
        p2->packet_length = 2222;
        memcpy(&p2->flow_key, &flow2, sizeof(flow2));
        insert_v4_flow_table(p2);
    }

    // Flow3
    for (int i = 0; i < 5; ++i) {
        struct v4_packet_info* p3 = alloc_v4_packet_info();
        memset(p3, 0x06, sizeof(struct v4_packet_info));
        p3->packet_length = 3333;
        memcpy(&p3->flow_key, &flow3, sizeof(flow3));
        insert_v4_flow_table(p3);
    }
}


void test_flow_table_inference() {
    // Simulate some pakcets
    generate_flow_sample();
    
    print_v4_flow_table();
    flow_table_inference();
    v4_flow_table_cleanup();
    return;
}

void test_pipe_communication() {
    quit_flag = false;
    int time_period = 3;
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGINT, signal_handler);

    // Simulate some flow
    generate_flow_sample();
    // print_v4_flow_table();

    main_lcore_handle_init();
    LOG_DEBUG("After main_lcore_handle_init().\n");
    int pre_ts = 0;
    int cur_ts = 0;
    int diff_ts = 0;
    while (!quit_flag) {
        cur_ts = time(NULL);
        diff_ts = cur_ts - pre_ts;
        if (diff_ts > time_period) {
            pre_ts = cur_ts;
            flow_table_inference();
        }
    }
    LOG_INFO("Clean up...\n");
    v4_flow_table_cleanup();
    main_lcore_handle_cleanup();
    return;
}

int main() {
    // test_flow_table_inference();
    test_pipe_communication();
    return 0;
}
