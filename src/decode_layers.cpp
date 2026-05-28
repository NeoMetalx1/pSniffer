#include "decode_layers.h"

void  print_eth_header (const u_char *packet) {

    int i;
    const struct ether_hdr *eth_header;

    eth_header = (const struct ether_hdr *)packet;
    
    std::cout << std::dec;
    std::cout << "[ Layer 2 :: Ethernet Header ]\n";
    std::cout << "[ Source: " << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<int>(eth_header->ether_src_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        std::cout << ":" << static_cast<int>(eth_header->ether_src_addr[i]);

    std::cout << std::dec;
    std::cout << "\tDest: " << std::hex << std::setw(2) << std::setfill('0') 
                            << static_cast<int>(eth_header->ether_dest_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        std::cout << ":" << static_cast<int>(eth_header->ether_dest_addr[i]);
    
    std::cout << std::dec;
    std::cout << "  Type:  " << eth_header->ether_type << " ]\n";
}


void  print_ip_header (const u_char *packet) {

    const struct ip_hdr *ip_header;

    ip_header = (const struct ip_hdr *)packet;

    std::cout << "[ Layer 3 :: IP Header ]\n";
    std::cout << "[ Source: " << inet_ntoa(ip_header->ip_src_addr);
    std::cout << "\tDest: " << inet_ntoa(ip_header->ip_dest_addr) << " ]\n";
    std::cout << "\t[ Type: " << (u_int)ip_header->ip_type;
    std::cout << "\tID: " << ntohs(ip_header->ip_id);
    std::cout << "\tLenght: " << ntohs(ip_header->ip_len) << " ]\n";

}


void  print_tcp_header (const u_char *packet) {
    
    const struct tcp_hdr *tcp_header;

    tcp_header = (const struct tcp_hdr *)packet;
    u_int header_size = 4 * tcp_header->tcp_offset;

    std::cout << "[ Layer 4 :: TCP Header ]\n";
    std::cout << "[ Src port: " << ntohs(tcp_header->tcp_src_port);
    std::cout << "\tDest port: " << ntohs(tcp_header->tcp_dest_port) << " ]\n";
    std::cout << "{ Seq: " << tcp_header->tcp_seq;
    std::cout << "\tAck: " << tcp_header->tcp_ack << " }\n";
    std::cout << "{ Header Size: " << header_size;
    std::cout << "\t Flag: ";
    
    if (tcp_header->tcp_flags & TCP_FIN)
        std::cout << "FIN ";
    if (tcp_header->tcp_flags & TCP_SYN)
        std::cout << "SYN ";
    if (tcp_header->tcp_flags & TCP_RST)
        std::cout << "RST ";
    if (tcp_header->tcp_flags & TCP_PUSH)
        std::cout << "PUSH ";
    if (tcp_header->tcp_flags & TCP_ACK)
        std::cout << "ACK ";
    if (tcp_header->tcp_flags & TCP_URG)
        std::cout << "URG ";
    if (tcp_header->tcp_flags & TCP_ECE)
        std::cout << "ECE ";
    if (tcp_header->tcp_flags & TCP_CWR)
        std::cout << "CWR ";

    std::cout << "}\n";
}
