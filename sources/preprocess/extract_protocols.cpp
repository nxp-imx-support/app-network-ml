#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <unordered_map>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <pthread.h>


#include "utils.h"
#include "extract_protocols.h"

/* IPv4 and IPv6 flow table */
std::unordered_map<uint64_t, std::vector<struct v4_packet_info*>> v4_flow_table;
pthread_mutex_t v4_flow_table_lock = PTHREAD_MUTEX_INITIALIZER;
std::unordered_map<uint64_t, std::vector<struct v6_packet_info*>> v6_flow_table;
std::vector<struct inferenced_flow_result> result_list;

/* Flow flag 
 * flag value: int 
 * 0 == Unknown
 * 1 == DDoS
 * 2 == Begin
 */
std::unordered_map<uint64_t, int> flow_flag;

uint64_t cnt;

/* Pipe for communication with AI inference process 
*  Only for main_lcore
*/
struct pollfd pfds[2];
bool have_response;
const char* pipe_reader = "/tmp/py_to_cpp";
const char* pipe_writer = "/tmp/cpp_to_py";
int reader_fd;
int writer_fd;


void main_lcore_handle_init() {
    // Set true for first request
    have_response = true;
    mkfifo(pipe_reader, 0666);
    mkfifo(pipe_writer, 0666);
    reader_fd = open(pipe_reader, O_RDONLY);
    writer_fd = open(pipe_writer, O_WRONLY);

    pfds[0].fd = reader_fd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
    pfds[1].fd = writer_fd;
    pfds[1].events = POLLOUT;
    pfds[1].revents = 0;

    LOG_INFO("pipe init over.\n");
    return;
}

void main_lcore_handle_cleanup() {
    close(reader_fd);
    close(writer_fd);
    return;
}

struct v4_packet_info* alloc_v4_packet_info() {
    struct v4_packet_info* ptr = (v4_packet_info*)malloc(sizeof(struct v4_packet_info));
    if (ptr) {
        memset(ptr, 0, sizeof(struct v4_packet_info));
        return ptr;
    }
    return NULL;
}

void free_v4_packet_info(struct v4_packet_info* ptr) {
    if (ptr) {
        free(ptr);
        ptr = NULL;
    }
}

void print_v4_packet_info(struct v4_packet_info* v4_pkt) {
    printf("=====packet begin======\n");
    printf("pkt information:\n time stamp: %lu:%lu, packet length: %d\n", 
        v4_pkt->ts.tv_sec, v4_pkt->ts.tv_usec, v4_pkt->packet_length);
    
    char src_ip[16] = { 0 };
	char dst_ip[16] = { 0 };
	inet_ntop(AF_INET, (void*)(&v4_pkt->flow_key.ip_src), src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, (void*)(&v4_pkt->flow_key.ip_dst), dst_ip, sizeof(dst_ip));
    int flag = v4_pkt->is_valid_flow_key ? 1 : 0;
    printf("is flow key valid? %d, flow key: (%s:%d->%s:%d, %d)\n", flag, src_ip, ntohs(v4_pkt->flow_key.port_src), 
        dst_ip, ntohs(v4_pkt->flow_key.port_dst), v4_pkt->flow_key.proto);
    
    printf("ip header length: %u, ip payload length: %u, proto val: %u\n", 
        v4_pkt->ip_hdr_len, v4_pkt->ip_payload_length, v4_pkt->proto_val);
    printf("trans hdr length: %u, highest layer: %u, protocols stack: %x\n",
        v4_pkt->trans_hdr_len, v4_pkt->highest_layer, v4_pkt->protocols_stack);
    printf("tcp length: %u, tcp ack: %u, tcp flags: %u, tcp windows: %u\n",
        v4_pkt->tcp_len, v4_pkt->tcp_ack, v4_pkt->tcp_flags, v4_pkt->tcp_win);
    printf("udp length: %u\n", v4_pkt->udp_len);
    printf("icmp type: %u\n", v4_pkt->icmp_type);
    printf("=====packet end=====\n");
}

void print_v6_packet_info(struct v6_packet_info* v6_pkt) {
    return;
}

/**
 * Note: It is not a standard judgement method for Ether frame. 
 * In the case, we only support TYPE=IPv4/IPv6
*/
static inline int 
is_valid_ether_pkt(struct rte_ether_hdr *pkt, uint32_t pkt_len) {
    // 1. The packet length need to be bigger than rte_ether_hdr
    if (pkt_len < sizeof(struct rte_ether_hdr))
        return -1;
    uint16_t eth_type = ntohs(pkt->ether_type);
    // 2. The type need to be IPv4 or IPv6
    if (eth_type != RTE_ETHER_TYPE_IPV4 && 
        eth_type != RTE_ETHER_TYPE_IPV6)
        return -1;
    return 0;
}

static inline int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct rte_ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;

	return 0;
}

static bool
is_valid_ipv6_pkt(const struct rte_ipv6_hdr *pkt)
{
	/* The IP version number must be 6 */
	if ((rte_be_to_cpu_32((pkt->vtc_flow)) >> 28) != 6)
		return false;

	return true;
}

// Make sure that src port > dst port
void order_trans_ports(void* flow_key, bool is_ipv4) {
    if (is_ipv4) {
        union v4_flow_key* flow_key_ptr = (union v4_flow_key*)flow_key;
        if (flow_key_ptr->port_src < flow_key_ptr->port_dst) {
            // Swap src and dst ports
            uint16_t tmp_port = flow_key_ptr->port_src;
            flow_key_ptr->port_src = flow_key_ptr->port_dst;
            flow_key_ptr->port_dst = tmp_port;

            uint32_t tmp_ip = flow_key_ptr->ip_dst;
            flow_key_ptr->ip_dst = flow_key_ptr->ip_src;
            flow_key_ptr->ip_src = tmp_ip;
        }
    } else {
        // TODO ipv6
    }
}

uint64_t calculate_flow_hash_key(uint64_t* block, size_t blk_size) {
    uint64_t ret = 0;
    const uint64_t *mask = NULL;
    std::hash<uint64_t> u64_hash;
    if (blk_size == V4_FLOW_KEY_SIZE) 
        mask = v4_key_mask;
    else if (blk_size = V6_FLOW_KEY_SIZE)
        mask = v6_key_mask;
    else {
        LOG_ERROR("blk size is invalid\n");
        return ret;
    }

    LOG_DEBUG_3("u64_hash(");
    for (size_t i = 0; i < blk_size; ++i) {
        ret ^= u64_hash(block[i] & mask[i]);
        LOG_DEBUG_3("%016lx ", block[i] & mask[i]);
    }
    LOG_DEBUG_3(")\n");

    return ret;
}

void handle_protocol_stack(struct rte_mbuf *pkt) {
    cnt += 1;
    LOG_DEBUG("No#%lu\n", cnt);
    // Point to protocol header fileds
    uint8_t* pro_ptr = NULL;

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (is_valid_ether_pkt(eth_hdr, pkt->pkt_len) < 0) {
        // rte_pktmbuf_free(pkt);
        LOG_ERROR("invalid ehter packet.\n");
        return;
    }
    pro_ptr = (uint8_t*)eth_hdr;
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct rte_ipv6_hdr *ipv6_hdr = NULL;

    struct v4_packet_info* v4_pkt = NULL;
    struct v6_packet_info* v6_pkt = NULL;

    // Handle IPv4 and IPv6
    if (eth_type == RTE_ETHER_TYPE_IPV4) {
        ipv4_hdr = (struct rte_ipv4_hdr*)(pro_ptr + sizeof(struct rte_ether_hdr));
	
        if (int ret = is_valid_ipv4_pkt(ipv4_hdr, pkt->pkt_len) < 0) {
            LOG_ERROR("invalid ipv4 packet. error code: %d\n", ret);
            // rte_pktmbuf_free(pkt);
            return;
        }

        v4_pkt = alloc_v4_packet_info();
        gettimeofday(&v4_pkt->ts, NULL);
        v4_pkt->packet_length = pkt->pkt_len;
        v4_pkt->ip_hdr_len = (ipv4_hdr->ihl & 0xF) << 2;
        v4_pkt->ip_payload_length = ntohs(ipv4_hdr->total_length) - v4_pkt->ip_hdr_len;
        v4_pkt->proto_val = ipv4_hdr->next_proto_id;
        v4_pkt->flags = ipv4_hdr->fragment_offset;
        v4_pkt->protocols_stack = PROSTACK_ETH + PROSTACK_IP;

        pro_ptr = (uint8_t*)ipv4_hdr + offsetof(struct rte_ipv4_hdr, time_to_live);
        memcpy(&(v4_pkt->flow_key), pro_ptr, sizeof(union v4_flow_key));
        order_trans_ports(&v4_pkt->flow_key, true);

    } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
        // IPv6 TODO.
        ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *,
            sizeof(struct rte_ether_hdr));
    } else {
        LOG_ERROR("invalid IP packet.\n");
    }
    
    // Handle TCP and UDP
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    if (v4_pkt && v4_pkt->proto_val == TCP_PROTOCOL_NUM) {
        tcp_hdr = (struct rte_tcp_hdr*)((uint8_t*)ipv4_hdr + v4_pkt->ip_hdr_len);
        v4_pkt->is_valid_flow_key = true;
        v4_pkt->trans_hdr_len = sizeof(struct rte_tcp_hdr);
        v4_pkt->tcp_len = pkt->pkt_len - sizeof(struct rte_tcp_hdr) - 
            sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr);
        v4_pkt->tcp_ack = tcp_hdr->recv_ack;
        v4_pkt->tcp_flags = tcp_hdr->tcp_flags;
        v4_pkt->tcp_win = tcp_hdr->rx_win;
        v4_pkt->protocols_stack += PROSTACK_TCP;
        v4_pkt->highest_layer = PROSTACK_TCP;
    }
    if (v6_pkt && v6_pkt->proto_val == TCP_PROTOCOL_NUM) {

    }
    if (v4_pkt && v4_pkt->proto_val == UDP_PROTOCOL_NUM) {
        udp_hdr = (struct rte_udp_hdr*)((uint8_t*)ipv4_hdr + v4_pkt->ip_hdr_len);
        v4_pkt->is_valid_flow_key = true;
        v4_pkt->trans_hdr_len = sizeof(struct rte_udp_hdr);
        v4_pkt->udp_len = pkt->pkt_len - sizeof(struct rte_udp_hdr) - 
            sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr);
        v4_pkt->protocols_stack += PROSTACK_UDP;
        v4_pkt->highest_layer = PROSTACK_UDP;
        
    }
    if (v6_pkt && v6_pkt->proto_val == UDP_PROTOCOL_NUM) {

    }

    // Handle ICMP
    // TODO

    // Handle higher layer
    if (v4_pkt && v4_pkt->is_valid_flow_key && v4_pkt->flow_key.port_dst == 443) {
        v4_pkt->protocols_stack += PROSTACK_SSL;
        v4_pkt->highest_layer = PROSTACK_SSL;
    }
    if (v4_pkt && v4_pkt->is_valid_flow_key && v4_pkt->flow_key.port_dst == 80) {
        v4_pkt->protocols_stack += PROSTACK_HTTP;
        v4_pkt->highest_layer = PROSTACK_HTTP;
    }

    // Match flow table and print debug message.
    uint64_t flow_hash_key = 0;
    if (v4_pkt && v4_pkt->is_valid_flow_key) {
        // print_v4_packet_info(v4_pkt);
        flow_hash_key = calculate_flow_hash_key(v4_pkt->flow_key.block, V4_FLOW_KEY_SIZE);
        LOG_DEBUG("flow hash key: %lu\n", flow_hash_key);

        pthread_mutex_lock(&v4_flow_table_lock);
        auto it = v4_flow_table.find(flow_hash_key);
        if (it != v4_flow_table.end() && it->second.size() < flow_len_threshold) {
            it->second.push_back(v4_pkt);
        } else {
            v4_flow_table.insert(
                std::pair<uint64_t, std::vector<struct v4_packet_info*>>(
                    flow_hash_key, std::vector<struct v4_packet_info*>({v4_pkt})));
            flow_flag.insert(std::pair<uint64_t, int>(flow_hash_key, 0));
        }
        pthread_mutex_unlock(&v4_flow_table_lock);
    }
    // TODO: IPv6 flow table
    if (v6_pkt) {
        print_v6_packet_info(v6_pkt);
    }
    return;
}

void print_v4_flow_table() {
    printf("In print_v4_flow_table()\n");
    if (v4_flow_table.empty())
        return;
    printf("v4 flow count: %lu\n", v4_flow_table.size());
    for (auto it = v4_flow_table.begin(); it != v4_flow_table.end(); ++it) {
        printf("========================\n");
        printf("=====New flow begin=====\n");
        auto vec = it->second;
        for (auto vec_it = vec.begin(); vec_it != vec.end(); ++vec_it)
            print_v4_packet_info(*vec_it);
        printf("=====Flow end=====\n");
        printf("==================\n");
    }
}

void v4_flow_table_cleanup() {
    // print_v4_flow_table();
    pthread_mutex_lock(&v4_flow_table_lock);
    if (v4_flow_table.empty())
        return;
    for (auto it = v4_flow_table.begin(); it != v4_flow_table.end(); ++it) {
        auto vec = it->second;
        for (auto vec_it = vec.begin(); vec_it != vec.end(); ++vec_it)
            free_v4_packet_info(*vec_it);
    }
    v4_flow_table.clear();
    pthread_mutex_unlock(&v4_flow_table_lock);
}

void v6_flow_table_cleanup() {

}

inline void normalize_packet(struct v4_packet_info* pkt, double (*time_win)[11], int i) {
    // Check i < 11
    if (i > 10) {
        LOG_ERROR("i must < 10, i: %d\n", i);
        return;
    }

    double f_val;
    f_val = 1 - (feature_value_range[1][1] - pkt->packet_length) / (double)(feature_value_range[1][1] - feature_value_range[1][0]);
    time_win[i][1] = f_val;
    LOG_DEBUG_3("packet_length: %d -> %lf\n", pkt->packet_length, f_val);
    f_val = 1 - (feature_value_range[2][1] - pkt->flags) / (double)(feature_value_range[2][1] - feature_value_range[2][0]);
    time_win[i][2] = f_val;
    LOG_DEBUG_3("flags: %d -> %lf\n", pkt->flags, f_val);
    f_val = 1 - (feature_value_range[3][1] - pkt->highest_layer) / (double)(feature_value_range[3][1] - feature_value_range[3][0]);
    time_win[i][3] = f_val;
    f_val = 1 - (feature_value_range[4][1] - pkt->protocols_stack) / (double)(feature_value_range[4][1] - feature_value_range[4][0]);
    time_win[i][4] = f_val;
    f_val = 1 - (feature_value_range[5][1] - pkt->tcp_len) / (double)(feature_value_range[5][1] - feature_value_range[5][0]);
    time_win[i][5] = f_val;
    f_val = 1 - (feature_value_range[6][1] - pkt->tcp_ack) / (double)(feature_value_range[6][1] - feature_value_range[6][0]);
    time_win[i][6] = f_val;
    f_val = 1 - (feature_value_range[7][1] - pkt->tcp_flags) / (double)(feature_value_range[7][1] - feature_value_range[7][0]);
    time_win[i][7] = f_val;
    f_val = 1 - (feature_value_range[8][1] - pkt->tcp_win) / (double)(feature_value_range[8][1] - feature_value_range[8][0]);
    time_win[i][8] = f_val;
    f_val = 1 - (feature_value_range[9][1] - pkt->udp_len) / (double)(feature_value_range[9][1] - feature_value_range[9][0]);
    time_win[i][9] = f_val;
    f_val = 1 - (feature_value_range[10][1] - pkt->icmp_type) / (double)(feature_value_range[10][1] - feature_value_range[10][0]);
    time_win[i][10] = f_val;
    return;
}

void transfer_to_feature(std::vector<struct v4_packet_info*>& flow, std::vector<pktFeaturePtr>& ret_feature_list) {
    size_t pkt_num = flow.size();
    if (pkt_num == 0)
        return;

    struct v4_packet_info* pkt = NULL;
    struct timeval* win_start_ts;
    win_start_ts = &(flow[0]->ts);
    double now = 0;
    double start_ts = 0;
    double diff = 0;

    double (*last_time_win)[11] = NULL;
    last_time_win = (pktFeaturePtr)malloc(win_max_pkt * 11 * sizeof(double));
    if (last_time_win == NULL) {
        LOG_ERROR("time_win alloc error.\n");
        return;
    }
    ret_feature_list.push_back(last_time_win);

    size_t i = 0;
    // pkt offset in time window
    int pkt_seq = 0;
    for (; i < pkt_num; ++i) {
        LOG_DEBUG_3("packet %u preproecss\n", i);
        pkt = flow[i];
        LOG_DEBUG_3("packet ts: %lds %ldus\n", pkt->ts.tv_sec, pkt->ts.tv_usec);
        now = pkt->ts.tv_sec + (double)pkt->ts.tv_usec * 1e-6;
        start_ts = win_start_ts->tv_sec + (double)win_start_ts->tv_usec * 1e-6;
        diff = now - start_ts;
        LOG_DEBUG_3("now timestamp: %lf, start timestamp: %lf, diff time: %lf\n", now, start_ts, diff);
        
        // Require a new time window.
        if (diff - win_time_period > 1e-6) {
            LOG_DEBUG("new time window require.\n");
            // Padding last window
            while (pkt_seq < win_max_pkt) {
                LOG_DEBUG_3("padding\n");
                last_time_win = ret_feature_list.back();
                memset(last_time_win + pkt_seq, 0, 11 * sizeof(double));
                ++pkt_seq;
            }
            win_start_ts = &(pkt->ts);
            double (*time_win)[11] = (pktFeaturePtr)malloc(win_max_pkt * 11 * sizeof(double));
            if (time_win == NULL) {
                LOG_ERROR("time_win alloc error.\n");
                return;
            }
            time_win[0][0] = 0;
            pkt_seq = 0;
            normalize_packet(pkt, time_win, pkt_seq);
            ++pkt_seq;
            ret_feature_list.push_back(time_win);
        } else {
            if (pkt_seq > win_max_pkt - 1) {
                LOG_DEBUG_3("pkt_seq > win_max_pkt, continue.\n");
                continue;
            }
            last_time_win = ret_feature_list.back();
            last_time_win[pkt_seq][0] = diff;
            LOG_DEBUG_3("last_time_win[%d][0] = %lf\n", pkt_seq, diff);
            normalize_packet(pkt, last_time_win, pkt_seq);
            ++pkt_seq;
        }
    }
    // padding
    while (pkt_seq < win_max_pkt) {
        LOG_DEBUG("padding\n");
        last_time_win = ret_feature_list.back();
        memset(last_time_win + pkt_seq, 0, 11 * sizeof(double));
        ++pkt_seq;
    }
    return;
}

void free_feature_list(std::vector<pktFeaturePtr>& feature_list) {
    for(size_t i = 0; i < feature_list.size(); ++i) {
        if (feature_list[i]) {
            free(feature_list[i]);
            feature_list[i] = NULL;
        }
    }
    feature_list.clear();
}

void calculate_flow_features(std::vector<pktFeaturePtr>& feature_list, std::vector<struct inferenced_flow_result>& result_list) {
    // Debug file
    FILE *log = fopen("infer_data_debug.txt", "a");
    fprintf(log, "\nIn calculate_flow_features.\n");
    LOG_DEBUG_3("In calculate_flow_features\n");

    struct inferenced_flow_result result_item;
    result_item.infer_result = 0.0;

    // walk through flow_table
    for (auto it = v4_flow_table.begin(); it != v4_flow_table.end(); ++it) {
        // If this flow was tagged, it doesn't need to inference again.
        if (flow_flag[it->first] != 0) {
            continue;
        }
        std::vector<struct v4_packet_info*>& item = it->second;
        LOG_DEBUG_3("flow length: %lu\n", item.size());
        fprintf(log, "flow length: %lu\n", item.size());
        // filter short flow
        if (item.size() < flow_len_threshold) {
            LOG_DEBUG_3("short flow\n");
            fprintf(log, "short flow\n");
            continue;
        }
        // splite time window in a flow
        transfer_to_feature(item, feature_list);
        while (result_list.size() < feature_list.size()) {
            result_item.flow_key_hash = it->first;
            result_list.push_back(result_item);
        }
    }
    // Print feature_list for debug
    for (auto it = feature_list.begin(); it != feature_list.end(); ++it) {
        pktFeaturePtr time_win = *it;
        fprintf(log, "window start\n");
        LOG_DEBUG_2("window start\n");
        for (int i = 0; i < win_max_pkt; ++i) {
            for (int j = 0; j < 11; ++j) {
                fprintf(log, "%lf ", time_win[i][j]);
                LOG_DEBUG_2("%lf ", time_win[i][j]);
            }
            fprintf(log, "\n");
            LOG_DEBUG_2("\n");
        }
        fprintf(log, "window end\n");
        LOG_DEBUG_2("window end\n");
    }
    fclose(log);
    return;
}

void flow_table_inference() {
    LOG_DEBUG("In flow table inference\n");
    int nfds = poll(pfds, 2, 200);
    ssize_t read_bytes = 0;
    ssize_t expected_data_length = 0;
    std::vector<pktFeaturePtr> feature_list;
    struct array_desc msg_desc;
    char* buffer = NULL;

    // pipe is not readable and writeable
    if (nfds <= 0)
        return;
    
    // If pipe is readable and not receive response yet.
    if (!have_response && pfds[0].revents & POLLIN) {
        LOG_DEBUG_3("pipe is readable.\n");
        read_bytes = read(reader_fd, &(msg_desc.row), sizeof(uint64_t));
        read_bytes = read(reader_fd, &(msg_desc.col), sizeof(uint64_t));
        LOG_DEBUG_3("msg_desc: %lu %lu\n", msg_desc.row, msg_desc.col);

        // It is a one dimensional array, like {1.0, 1.0, 0.0, 0.0, 1.0, 0.0, ...}
        expected_data_length = msg_desc.row * msg_desc.col * sizeof(double);
        LOG_DEBUG_3("expected array size: %ld\n", expected_data_length);
        buffer = (char*)malloc(expected_data_length);
        read_bytes = read(reader_fd, buffer, expected_data_length);
        LOG_DEBUG_3("read %ld bytes from pipe.\n", read_bytes);
        std::vector<double> infer_result_arr;
        unpack_double_type_array(buffer, expected_data_length, infer_result_arr);
        free(buffer);
        buffer = NULL;
        // Corelate inference result, and vote to update flow_flag
        size_t r_l_length = result_list.size();
        if (r_l_length != infer_result_arr.size()) {
            LOG_ERROR("Inference result get error: array length doesn't match! result_list size: %lu\n", r_l_length);
            return;
        }
        
        if (r_l_length == 0) {
            LOG_ERROR("Inference result get error: array length is 0!\n");
            return;
        }
        
        for (int i = 0; i < r_l_length; ++i) {
            result_list[i].infer_result = infer_result_arr[i];
        }
        // Update flow_flag, need to vote
        int ddos_cnt = 0;
        int total_cnt = 0;
        uint64_t key_tmp = result_list[0].flow_key_hash;
        for (int i = 0; i < r_l_length; ++i) {
            if (key_tmp != result_list[i].flow_key_hash) {
                flow_flag[key_tmp] = (total_cnt - ddos_cnt > ddos_cnt) ? 2 : 1;
                ddos_cnt = 0;
                total_cnt = 0;
                key_tmp = result_list[i].flow_key_hash;
            }
            if (result_list[i].infer_result == 1.0)
                ++ddos_cnt;
            ++total_cnt;
        }
        flow_flag[key_tmp] = (total_cnt - ddos_cnt > ddos_cnt) ? 2 : 1;
        // Debug flow_flag
        for (auto it = flow_flag.begin(); it != flow_flag.end(); ++it) {
            LOG_DEBUG("%lu => %d\n", it->first, it->second);
        }
        // Clean
        have_response = true;
        result_list.clear();
    }

    // If pipe is writeable and last inference is over.
    if (have_response && pfds[1].revents & POLLOUT) {
        LOG_DEBUG_3("pipe is writeable.\n");
        calculate_flow_features(feature_list, result_list);
        if (feature_list.size() == 0 || result_list.size() == 0) {
            LOG_INFO("No flow need to inference");
            return;
        }
        // Write to pipe.
        // Calculate the packets amount = time window count * packets per window
        msg_desc.row = feature_list.size() * win_max_pkt;
        msg_desc.col = 11;
        LOG_DEBUG("msg_desc: row=%lu, col=%lu\n", msg_desc.row, msg_desc.col);
        char* buf = pack_double_type_array(msg_desc, win_max_pkt, feature_list);
        for (auto it = feature_list.begin(); it != feature_list.end(); ++it) {
            free(*it);
            *it = NULL;
        }
        free_feature_list(feature_list);
        if (buf == NULL)
            return;
        ssize_t writen_bytes = 0;
        writen_bytes = write(writer_fd, &msg_desc, sizeof(msg_desc));
        LOG_DEBUG("%ld bytes to write.\n", writen_bytes);
        LOG_DEBUG("%lu bytes need to be writen\n", msg_desc.row * msg_desc.col * sizeof(double));
        writen_bytes = write(writer_fd, buf, msg_desc.row * msg_desc.col * sizeof(double));
        LOG_DEBUG("%lu bytes to write.\n", writen_bytes);
        free(buf);
        buf = NULL;
        have_response = false;
    }
}

// This function is only for debug.
void insert_v4_flow_table(struct v4_packet_info* v4_pkt) {
    LOG_DEBUG_3("flow key block: %016lx %016lx\n", v4_pkt->flow_key.block[0], v4_pkt->flow_key.block[1]);
    uint64_t flow_hash_key = calculate_flow_hash_key(v4_pkt->flow_key.block, V4_FLOW_KEY_SIZE);
    LOG_DEBUG_3("flow hash key: %lu\n", flow_hash_key);
    auto it = v4_flow_table.find(flow_hash_key);
    if (it != v4_flow_table.end()) {
        it->second.push_back(v4_pkt);
    } else {
        v4_flow_table.insert(
            std::pair<uint64_t, std::vector<struct v4_packet_info*>>(
                flow_hash_key, std::vector<struct v4_packet_info*>({v4_pkt})));
        flow_flag.insert(std::pair<uint64_t, int>(flow_hash_key, 0));
    }
}


