#!/bin/bash
pkill -f ghost-server; pkill -f ghost-client; pkill -f xray-test; pkill -f origin; pkill -f http2_tls
sleep 1

# 1. Запуск сервисов
setsid /tmp/origin > /dev/null 2>&1 < /dev/null &
setsid /root/http2_tls > /dev/null 2>&1 < /dev/null &
sleep 2

cd /root/ghost-quic-v2
# Xray (Vision)
setsid /tmp/xray-test -c /tmp/xray-server-A.json > /dev/null 2>&1 < /dev/null &
sleep 1
setsid /tmp/xray-test -c /tmp/xray-client-A.json > /dev/null 2>&1 < /dev/null &
sleep 2

# Ghost
PRIV=$(grep '^PRIVATE=' secrets/reality_private.txt | cut -d= -f2)
PUB=$(grep '^PUBLIC=' secrets/reality_private.txt | cut -d= -f2)
setsid env REALITY_PRIVATE=$PRIV REALITY_DEST=www.microsoft.com:443 /tmp/ghost-server-finalfix > /dev/null 2>&1 < /dev/null &
for i in {1..10}; do ss -tln | grep -q 9449 && break; sleep 1; done

echo "=== CAPTURE GHOST (10 sessions) ==="
tcpdump -i lo -s 0 -B 4096 -nn -w /root/ghost_final.pcap "tcp port 9449" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..10}; do
    pkill -f ghost-client; sleep 0.3
    setsid env REALITY_PUBLIC=$PUB REALITY_ADDR=127.0.0.1:9449 /tmp/ghost-client-finalfix -socks=127.0.0.1:1085 > /dev/null 2>&1 < /dev/null &
    sleep 0.5
    curl -s --socks5 127.0.0.1:1085 http://127.0.0.1:9990/large -o /dev/null
done
sleep 1; kill $TCPDUMP_PID; pkill -f ghost-client

echo "=== CAPTURE VISION (10 sessions) ==="
tcpdump -i lo -s 0 -B 4096 -nn -w /root/vision_final.pcap "tcp port 9445" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..10}; do curl -s --socks5 127.0.0.1:1081 http://127.0.0.1:9990/large -o /dev/null; done
sleep 1; kill $TCPDUMP_PID

echo "=== CAPTURE HTTP/2 (10 sessions) ==="
tcpdump -i lo -s 0 -B 4096 -nn -w /root/http2_final.pcap "tcp port 8444" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..10}; do curl -k -s https://127.0.0.1:8444/ -o /dev/null; done
sleep 1; kill $TCPDUMP_PID

echo "=== PCAP SIZES ==="
ls -la /root/*_final.pcap

echo "=== 1. GHOST vs HTTP/2 ==="
cd /root/ghost-quic-v2/bench
python3 ml_tls.py ghost:/root/ghost_final.pcap http2:/root/http2_final.pcap

echo "=== 2. VISION vs HTTP/2 ==="
python3 ml_tls.py vision:/root/vision_final.pcap http2:/root/http2_final.pcap
