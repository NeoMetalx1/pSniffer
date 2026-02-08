all:
	g++ -std=c++17 src/pcap_sniff.cpp -l pcap -o sniffer
