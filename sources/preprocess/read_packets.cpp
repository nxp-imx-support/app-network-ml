#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <string.h>
#include "extract_protocols.h"
#include <vector>
#include "nlohmann/json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

const int ETH_HDR_LEN = 14;


// extract packet info
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct packet_info *pkt_info = alloc_packet_info();
    if (pkt_info == NULL) {
        printf("[ERROR] malloc failed for struct packet_info\n");
        return;
    }
    
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);
    pkt_info->ts = header->ts;
    pkt_info->packet_length = header->len;
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    int status;
    status = extract_ip_layer(packet + ETH_HDR_LEN, ntohs(eth_header->ether_type), pkt_info);
    if (status < 0) {
        printf("[ERROR] Invalid IP/IPv6 packet.\n");
        return;
    }

    char highest_layer[10] = {0};
    __u16 protocol_stack = 0;
    protocol_stack |= PROSTACK_ETH;
    protocol_stack |= PROSTACK_IP;

    if (pkt_info->proto_val == IPPROTO_ICMP or pkt_info->proto_val == IPPROTO_ICMPV6) {
        pkt_info->icmp_type = *(packet + ETH_HDR_LEN + pkt_info->ip_hdr_len);
        strncpy(highest_layer, "icmp\0", sizeof(highest_layer));
    } else if (pkt_info->proto_val == IPPROTO_TCP or pkt_info->proto_val == IPPROTO_UDP) {
        status = extract_transmission_layer(packet + ETH_HDR_LEN + pkt_info->ip_hdr_len,
            pkt_info->proto_val, pkt_info);
        if (status < 0) {
            printf("[ERROR] Invalid TCP/UDP packet.\n");
            return;
        }
        if (pkt_info->trans_hdr_len == 8) {
            protocol_stack |= PROSTACK_UDP;
            pkt_info->udp_len = pkt_info->packet_length - 8;
            // Simply judge the high layer protocol. Actually it should be detected by payload.
            if (pkt_info->src_port == 53 or pkt_info->dst_port == 53) {
                strncpy(pkt_info->highest_layer, "dns\0", 10);
                protocol_stack |= PROSTACK_DNS;
            } else {
                strncpy(pkt_info->highest_layer, "udp\0", 10);
            }
        }
        else {
            protocol_stack |= PROSTACK_TCP;
            pkt_info->tcp_len = pkt_info->packet_length - pkt_info->trans_hdr_len;
            if (pkt_info->dst_port == 443 or pkt_info->src_port == 443) {
                strncpy(pkt_info->highest_layer, "ssl\0", 10);
                protocol_stack |= PROSTACK_SSL;
            } else if (pkt_info->dst_port == 80 or pkt_info->src_port == 80) {
                strncpy(pkt_info->highest_layer, "http\0", 10);
                protocol_stack |= PROSTACK_HTTP;
            } else {
                strncpy(pkt_info->highest_layer, "tcp\0", 10);
            }
        }
            
    } else {
        printf("Proto type: %d\n", pkt_info->proto_val);
        return;
    }

    pkt_info->protocols_stack = protocol_stack;

    // print_packet_info(pkt_info);

    struct packet_list* ptr = (struct packet_list*)args;
    ptr->vec.push_back(*pkt_info);

    free_packet_info(pkt_info);
    return;
}

json pkt_info_to_json(struct packet_list* pkt_list) {
    json j_ret = {
        { "ret_arr", json::array() }
    };
    for (auto it = pkt_list->vec.begin(); it != pkt_list->vec.end(); it++) {
        std::ostringstream oss;
        oss << it->ts.tv_sec << "." << it->ts.tv_usec;

        json item = {
            {"src_ip", it->src_ip},
            {"dst_ip", it->dst_ip},
            {"src_port", it->src_port},
            {"dst_port", it->dst_port},
            {"proto_type", it->proto_type},
            {"sniff_time", oss.str()},
            {"packet_length", it->packet_length},
            {"highest_layer", it->highest_layer},
            {"ip_flags", it->flags},
            {"protocols_stack", it->protocols_stack},
            {"tcp_len", it->tcp_len},
            {"tcp_ack", it->tcp_ack},
            {"tcp_flags", it->tcp_flags},
            {"tcp_win", it->tcp_win},
            {"udp_len", it->udp_len},
            {"icmp_type", it->icmp_type}
        };
        j_ret["ret_arr"].push_back(item);
    }
    return j_ret;
}

int start_capture() {    
    const char *device = "ens160";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 100;
    u_char *my_arguments = NULL;
    char c;

    if (device == NULL) {
        printf("Requires -i option to specify a NIC\n");
        return 0;
    }

    int uid = geteuid();
    printf("Current user: %d\n", uid);
    if (uid != 0) {
        printf("Need to run as root\n");
        return 0;
    }

    struct packet_list pkt_list;

    handle = pcap_create(device, error_buffer);
    if (handle == NULL) {
        printf("Unable to open the capture device: %s\n", device);
        return 0;
    }

    pcap_set_buffer_size(handle, 200 * 1024 * 1024);
    pcap_set_timeout(handle, 20);
    pcap_set_snaplen(handle, snapshot_length);
    pcap_activate(handle);
    printf("Starting capture on %s\n", device);
    pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*)&pkt_list);

    pcap_close(handle);

    printf("pkt num: %ld\n", pkt_list.vec.size());
    print_packet_info(&pkt_list.vec[6]);

    return 0;
}

int offline_pcap_read() {
    char err_buf[PCAP_ERRBUF_SIZE];
    const char* pcap_file = "/home/nxg01813/Code/lucid-ddos/sample-dataset/CIC-DDoS-2019-Benign.pcap";
    pcap_t* handle = pcap_open_offline(pcap_file, err_buf);
    struct packet_list pkt_list;

    pcap_loop(handle, -1, my_packet_handler, (u_char*)&pkt_list);

    pcap_close(handle);
    printf("pkt num: %ld\n", pkt_list.vec.size());

    json j_ret = pkt_info_to_json(&pkt_list);
    std::string jsonString = j_ret.dump();

    // To txt file, for debug
    // std::ofstream fout;
    // fout.open("./tmp.txt", std::ios::out);
    // fout << jsonString << std::endl;
    // fout.close();

    // To pipe
    const char* fifoPath = "/tmp/pcap_fifo";
    mkfifo(fifoPath, 0666);
    std::ofstream fifoStream(fifoPath);
    if (!fifoStream.is_open()) {
        std::cerr << "Error opening FIFO for writer." << std::endl;
        return -1;
    }
    fifoStream << jsonString;
    fifoStream.close();
    unlink(fifoPath);

    return 0;
}