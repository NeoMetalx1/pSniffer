all:
	g++ -std=c++17 -Iinclude src/packet_handler.cpp src/main.cpp -l pcap -o sniffer
