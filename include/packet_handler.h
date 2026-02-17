#pragma once

#include <iostream>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <pcap.h>

class P_handler {
private:
    char errbuf[PCAP_ERRBUF_SIZE];

    //  Packet parts
    struct pcap_pkthdr  p_header;
    const  u_char       *packet;

    //  Device parts
    pcap_if_t   *alldevs;
    pcap_if_t   *device;
    pcap_t      *pcap_handle;

    //  Debug tools
    void p_err(const std::string& message, const char *errbuf); 
    void p_debug(const std::string& message);
    void p_device();

    //  Init methods
    void initDevice();
    void initHandle();

    //  Packet processing
    static void p_dumpCallback(u_char* user_args,
                               const struct pcap_pkthdr* _p_header,
                               const u_char* _packet);

public:
    //  Constructor, Destructor
    P_handler();
    ~P_handler();

    //  Capture packets
    void capturePacket(const unsigned int packet_count);
};
