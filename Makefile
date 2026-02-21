all:
	g++ -std=c++17 -Iinclude src/packet_handler.cpp src/decode_layers.cpp src/main.cpp -l pcap -o sniffer
