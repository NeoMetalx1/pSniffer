#pragma once

#include "packet_handler.h"


// ethernet structure taken from if_ethernet.h
// ethernet header 
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr {
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];  // Target MAC-address
    unsigned char ether_src_addr[ETHER_ADDR_LEN];   // Source MAC-address
    unsigned short ether_type;  // Ethernet-packet type
}


// IP structure taken from ip.h (RFC 791 internet-datagram)
// IP header
struct ip_hdr {
    unsigned char ip_version_and_header_lenght;  // Verison and header lenght
    unsigned char  ip_tos;           //  Type of service
    unsigned short ip_len;           //  Total lenght
    unsigned short ip_id;            //  ID number
    unsigned short ip_frag_offset;   //  Element offset and flags
    unsigned char  ip_ttl;           //  Time of life
    unsigned char  ip_proto_type;    //  Protocol type
    unsigned short ip_checksum;      //  Checksum
    unsigned int   ip_src_addr;      //  Source IP address
    unsigned int   ip_dest_addr;     //  Destination IP address
}

// TCP structure taken from tcp.h (RFC 793 tcp header format)
// TCP structure
struct tcp_hdr {
    unsigned short tcp_src_port;    //  TCP source port
    unsigned short tcp_dest_port;   //  TCP destination port
    unsigned int   tcp_seq;         //  TCP queue number
    unsigned int   tcp_ack;         //  TCP accept number
    unsigned char  tcp_reserved:4;  //  Reserve 4 bits from 6 reserved bits
    unsigned char  tcp_offsed:4;    //  Data offset
    unsigned char  tcp_flags;       //  TCP flags

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

    unsigned short tcp_window       //  TCP window;
    unsigned short tcp_checksum;    //  Checksum;
    unsigned short tco_urgent;      //  Urgency pointer
}

