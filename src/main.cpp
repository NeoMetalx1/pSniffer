#include "packet_handler.h"

int main() {

    P_handler sniffer;

    while(true) {
        sniffer.capturePacket();
    }



    return 0;
}
