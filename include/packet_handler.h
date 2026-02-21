#pragma once

#include <iostream>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <pcap.h>

#include "decode_layers.h"

//  Packet print options
#define P_RAW 1
#define P_LAYERS 2


class P_handler {
private:
    char errbuf[PCAP_ERRBUF_SIZE];

    //  Packet parts
    struct pcap_pkthdr  p_header;
    const  u_char       *packet;

    //  Device parts
    pcap_if_t   *alldevs     = nullptr;
    pcap_if_t   *device      = nullptr;
    pcap_t      *pcap_handle = nullptr;

    //  Debug tools
    void p_err(const std::string& message, const char *errbuf); 
    void p_debug(const std::string& message);
    void p_device();

    //  Init methods
    void initDevice();
    void initHandle();

    //  Packet processing
    static void p_dumpRawCallback(u_char* user_args,
                               const struct pcap_pkthdr* _p_header,
                               const u_char* _packet);

    static void p_dumpLayersCallback(u_char* user_args,
                               const struct pcap_pkthdr* _p_header,
                               const u_char* _packet);
public:
    //  Constructor, Destructor
    P_handler();
    ~P_handler();

    //  Capture packets
    void capturePacket(const unsigned int packet_count, const unsigned int print_option);
};
