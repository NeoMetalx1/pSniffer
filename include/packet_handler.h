#pragma once

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

class P_handler {
private:
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr  p_header;
    const  u_char       *packet;

    pcap_if_t   *alldevs;
    pcap_if_t   *device;
    pcap_t      *pcap_handle;

    //

    void p_err(const std::string& message, const char *errbuf); 
    void p_debug(const std::string& message);
    void p_device();

    //
    
    void setDevice();
    void initHandle();

    static void packetDump(u_char* user_args, const struct pcap_pkthdr* _p_header, const u_char* _packet );

public:
    P_handler();
    ~P_handler();

    void capturePacket(const unsigned int packet_count);
};
