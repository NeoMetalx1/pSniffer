#include "packet_handler.h"

// constructor and destructor

P_handler::P_handler() {
    setDevice();
    initHandle();
}

P_handler::~P_handler() {
    pcap_freealldevs(alldevs);
    pcap_close(pcap_handle);
}

// private

void  P_handler::p_err (const std::string& message, const char *errbuf) {
    std::cout << "[ERROR] " << message << " | " << errbuf << '\n';
    return; 
}


void  P_handler::p_debug (const std::string& message) {
    std::cout << "[DEBUG] " << message << '\n';
    return;
}


void P_handler::p_device () {

    if (!device) {
        p_err("device empty", errbuf);            
        return;
    }

    std::cout << "[DEVICE] : "<< device->name << '\n';
    return;
}


void  P_handler::setDevice () {

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        p_err("Can't find devices", errbuf);
        return;
    }

    device = alldevs;
    if (!device) {
        p_err("No device found", errbuf);
        pcap_freealldevs(alldevs);
        return;
    }
}


void  P_handler::initHandle () {
    
    pcap_handle = pcap_open_live(
        device->name,
        4096,
        1,
        1000,
        errbuf
    );

    if (!pcap_handle) {
        p_err("Failed to open handler", errbuf);
        pcap_freealldevs(alldevs);
        return;
    }
}


void  P_handler::packetDump (const unsigned char *packet, const unsigned int lenght) {
    
    unsigned int byte;
    unsigned int i, j;

    for (i = 0; i < lenght; i++) {
        byte = packet[i];
        printf("%02x ", byte);

        if (((i % 16) == 15) || (i == lenght - 1)) {

            for (j = 0; j < 15-(i%16); j++)
                printf("   ");
            printf(" |");
                
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = packet[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}


//public

void  P_handler::capturePacket () {
    
    packet = pcap_next(pcap_handle, &p_header);
    std::cout << "----------------------------------------------------\n";
    std::cout << "[+] Received packet (size: " << p_header.len << "): \n";
    packetDump(packet, p_header.len);

    if (!packet) {
        std::cout << "[!] No received packets\n";
        return;
    }
    return;
}

