#include "decode_layers.h"

void  decode_eth (const u_char *p_header) {

    int i;
    const struct ether_hdr *ethernet_header;

    ethernet_header = (const struct ether_hdr *)p_header;
    
    std::cout << std::dec;
    std::cout << "[ Layer 2 :: Ethernet Header ]\n";
    std::cout << "[ Source: " << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<int>(ethernet_header->ether_src_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        std::cout << ":" << static_cast<int>(ethernet_header->ether_src_addr[i]);

    std::cout << std::dec;
    std::cout << "\tDest: " << std::hex << std::setw(2) << std::setfill('0') 
                            << static_cast<int>(ethernet_header->ether_dest_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        std::cout << ":" << static_cast<int>(ethernet_header->ether_dest_addr[i]);
    
    std::cout << std::dec;
    std::cout << "  Type:  " << ethernet_header->ether_type << " ]\n";
}


void  decode_ip (const u_char *p_header) {
    
    const struct ip_hdr *ip_header;

    ip_header = (const struct ip_hdr *)p_header;

    std::cout << "[ Layer 3 :: IP Header ]\n";
    std::cout << "[ Source: " << inet_ntoa(ip_header->ip_src_addr);
    std::cout << "\tDest: " << inet_ntoa(ip_header->ip_dest_addr) << " ]\n";
    std::cout << "\t[ Type: " << (u_int)ip_header->ip_type;
    std::cout << "\tID: " << ntohs(ip_header->ip_id);
    std::cout << "\tLenght: " << ntohs(ip_header->ip_len) << " ]\n";

}


void  decode_tcp (const u_char *p_header) {
    
    const struct tcp_hdr *tcp_header;

    tcp_header = (const struct tcp_hdr *)p_header;
    u_int header_size = 4 * tcp_header->tcp_offset;

    std::cout << "[ Layer 4 :: TCP Header ]\n";
    std::cout << "[ Src port: " << ntohs(tcp_header->tcp_src_port);
    std::cout << "\tDest port: " << ntohs(tcp_header->tcp_dest_port) << " ]\n";
    std::cout << "{ Seq: " << tcp_header->tcp_seq;
    std::cout << "\tAck: " << tcp_header->tcp_ack << " }\n";
    std::cout << "{ Header Size: " << header_size;
    std::cout << "\t Flag: ";
    
    switch (tcp_header->tcp_flags) {
        case TCP_FIN:
            std::cout << "FIN ";
            break;
        case TCP_SYN:
            std::cout << "SYN ";
            break;
        case TCP_RST:
            std::cout << "RST ";
            break;
        case TCP_PUSH:
            std::cout << "PUSH ";
            break;
        case TCP_ACK:
            std::cout << "ACK ";
            break;
        case TCP_URG:
            std::cout << "URG ";
            break;
        case TCP_ECE:
            std::cout << "ECE ";
            break;
        case TCP_CWR:
            std::cout << "CWR ";
            break;
        default:
            std::cout << "NONE ";
            break;
    }
    std::cout << "}\n";
}
