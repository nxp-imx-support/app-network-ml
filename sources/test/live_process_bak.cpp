#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>

const int ETH_HDR_LEN = 14;

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    // const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    struct ip_header *ipheader = (struct ip_header*)(packet + ETH_HDR_LEN);


    /* Header lengths in bytes */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ETH_HDR_LEN;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    /*  
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */

    return;
}

int main(int argc, char **argv) {    
    const char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 100;
    u_char *my_arguments = NULL;
    char c;

    while ((c = getopt(argc, argv, "i:")) != -1) {
        printf("c : %c\n", c);
        switch (c) {
            case 'i':
                device = optarg;
                break;
            case '?':
                if (optopt == 'i')
                    printf("Option i requires an argumnet.\n");
                else
                    printf("Unknow option '-%c'\n", optopt);
                break;
        }
    }

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

    handle = pcap_create(device, error_buffer);
    if (handle == NULL) {
        printf("Unable to open the capture device: %s\n", device);
        return 0;
    }
    pcap_set_buffer_size(handle, 200 * 1024 * 1024);
    pcap_set_timeout(handle, 100);
    pcap_set_snaplen(handle, snapshot_length);
    pcap_activate(handle);
    printf("Starting capture on %s\n", device);
    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}