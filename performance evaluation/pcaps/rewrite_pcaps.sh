#!/bin/bash
tcprewrite --infile=TCP_1500.pcap --outfile=TCP_1500.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=TCP_256.pcap --outfile=TCP_256.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=TCP_512.pcap  --outfile=TCP_512.pcap  --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=TCP_67.pcap --outfile=TCP_67.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 -D 127.0.0.1:10.0.0.3 --fixcsum
tcprewrite --infile=UDP_1500.pcap --outfile=UDP_1500.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=UDP_256.pcap --outfile=UDP_256.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=UDP_43.pcap --outfile=UDP_43.pcap --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=UDP_512.pcap  --outfile=UDP_512.pcap  --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
tcprewrite --infile=imix.pcap  --outfile=imix.pcap  --enet-dmac=40:a6:b7:5f:dd:91 --enet-smac=b8:ce:f6:04:8b:71 --fixcsum
