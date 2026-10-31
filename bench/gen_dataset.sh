#!/bin/bash
echo "=== GENERATING DATASETS (50 SESSIONS EACH) ==="

# 1. VISION (Port 1081)
echo "Capturing Vision..."
tcpdump -i lo -nn -w /root/vision_multi.pcap "tcp port 9445" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do curl -s --socks5 127.0.0.1:1081 http://127.0.0.1:9990/large -o /dev/null; done
sleep 1
kill $TCPDUMP_PID

# 2. GHOST (Port 1085)
echo "Capturing Ghost..."
tcpdump -i lo -nn -w /root/ghost_multi.pcap "tcp port 9449" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do curl -s --socks5 127.0.0.1:1085 http://127.0.0.1:9990/large -o /dev/null; done
sleep 1
kill $TCPDUMP_PID

# 3. HTTP/2 (Port 8444)
echo "Capturing HTTP/2..."
tcpdump -i lo -nn -w /root/http2_multi.pcap "tcp port 8444" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do curl -k -s https://127.0.0.1:8444/ -o /dev/null; done
sleep 1
kill $TCPDUMP_PID

echo "=== DATASETS CAPTURED ==="
