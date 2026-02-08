#include <pcap.h>
#include <iostream>

int main() {
    struct pcap_pkthdr packet_header;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *pcap_handle;
    const u_char *packet;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs failed: " << errbuf << std::endl;
        return 1;
    }

    device = alldevs;
    if (!device) {
        std::cerr << "No devices found" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "Using device: " << device->name << std::endl;

    pcap_handle = pcap_open_live(
        device->name,
        4096,
        1,
        1000,
        errbuf
    );

    if (!pcap_handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    for (int i = 0; i < 3; i++) {
        packet = pcap_next(pcap_handle, &packet_header);
        std::cout << "[+] Received packet (size: " << packet_header.len << "): \n";
    }

    pcap_freealldevs(alldevs);
    pcap_close(pcap_handle);

    return 0;
}

