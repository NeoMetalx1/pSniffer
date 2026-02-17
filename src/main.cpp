#include "packet_handler.h"

int main() {


    P_handler sniffer;
    std::cout << "[MAIN] CREATE OBJECT\n";


    sniffer.capturePacket(-1);


    std::cout << "[MAIN] END\n";
    return 0;
}
