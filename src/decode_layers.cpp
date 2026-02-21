#include "decode_layers.h"

void decode_eth (const u_char *p_header) {

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
