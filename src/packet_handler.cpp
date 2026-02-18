#include "packet_handler.h"

// constructor and destructor

P_handler::P_handler() {
    initDevice();
    initHandle();
}

P_handler::~P_handler() {
    pcap_freealldevs(alldevs);
    pcap_close(pcap_handle);
}


// private

void  P_handler::p_err (const std::string& message, const char *errbuf) {
    throw std::runtime_error(message + errbuf);
}


void  P_handler::p_debug (const std::string& message) {
    std::cout << "[DEBUG] " << message << '\n';
}

void P_handler::p_device () {

    if (!device) {
        p_err("device empty", errbuf);            
    }

    std::cout << "[DEVICE] : "<< device->name << '\n';
}



void  P_handler::initDevice () {

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        p_err("Can't find devices", errbuf);
    }

    device = alldevs;
    if (!device) {
        p_err("No device found", errbuf);
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
    }
}



void  P_handler::p_dumpCallback (u_char* user_args,
                                 const struct pcap_pkthdr* _p_header,
                                 const u_char* _packet) {
    
    unsigned int byte;
    unsigned int i, j;

    std::cout << "-----------------------------------------------------\n";
    std::cout << "[+] Received packet (size: " << _p_header->len << "):\n";

    for (i = 0; i < _p_header->len; i++) {
        byte = _packet[i];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        
        if (((i % 16) == 15) || (i == _p_header->len - 1)) {

            for (j = 0; j < 15-(i%16); j++)
                std::cout << "   ";
            std::cout << " |";
                
            std::cout << std::dec;
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = _packet[j];
                if ((byte > 31) && (byte < 127))
                    std::cout << static_cast<char>(byte);
                else
                    std::cout << ".";
            }
            std::cout << std::endl;
        }
    }
}


//public

void  P_handler::capturePacket (const unsigned int packet_count) {

    if (!pcap_handle) {
        p_err("Can't capture (handle error)", errbuf);
    }

    pcap_loop(pcap_handle, packet_count, p_dumpCallback, NULL);
}

