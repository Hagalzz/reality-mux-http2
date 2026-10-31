#!/bin/bash
echo "=== 1. CLEANUP ==="
pkill -f ghost-server; pkill -f ghost-client; pkill -f xray-test; pkill -f origin; pkill -f http2_tls
sleep 1

echo "=== 2. START ORIGIN & HTTP/2 ==="
setsid /tmp/origin > /dev/null 2>&1 < /dev/null &
setsid /root/http2_tls > /dev/null 2>&1 < /dev/null &
sleep 2

echo "=== 3. START VISION (XRAY A) ==="
cd /root/ghost-quic-v2
setsid /tmp/xray-test -c /tmp/xray-server-A.json > /dev/null 2>&1 < /dev/null &
sleep 1
setsid /tmp/xray-test -c /tmp/xray-client-A.json > /dev/null 2>&1 < /dev/null &
sleep 2

echo "=== 4. START GHOST (FINAL FIX) ==="
PRIV=$(grep '^PRIVATE=' secrets/reality_private.txt | cut -d= -f2)
PUB=$(grep '^PUBLIC=' secrets/reality_private.txt | cut -d= -f2)
setsid env REALITY_PRIVATE=$PRIV REALITY_DEST=www.microsoft.com:443 /tmp/ghost-server-finalfix > /dev/null 2>&1 < /dev/null &
for i in {1..10}; do ss -tln | grep -q 9449 && break; sleep 1; done

echo "=== 5. CAPTURE GHOST (50 SESSIONS) ==="
tcpdump -i lo -nn -w /root/ghost_final.pcap "tcp port 9449" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do
    pkill -f ghost-client; sleep 0.2
    setsid env REALITY_PUBLIC=$PUB REALITY_ADDR=127.0.0.1:9449 /tmp/ghost-client-finalfix -socks=127.0.0.1:1085 > /dev/null 2>&1 < /dev/null &
    sleep 0.3
    curl -s --socks5 127.0.0.1:1085 http://127.0.0.1:9990/large -o /dev/null
done
sleep 1
kill $TCPDUMP_PID; pkill -f ghost-client

echo "=== 6. CAPTURE VISION (50 SESSIONS) ==="
tcpdump -i lo -nn -w /root/vision_final.pcap "tcp port 9445" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do curl -s --socks5 127.0.0.1:1081 http://127.0.0.1:9990/large -o /dev/null; done
sleep 1
kill $TCPDUMP_PID

echo "=== 7. CAPTURE HTTP/2 (50 SESSIONS) ==="
tcpdump -i lo -nn -w /root/http2_final.pcap "tcp port 8444" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
for i in {1..50}; do curl -k -s https://127.0.0.1:8444/ -o /dev/null; done
sleep 1
kill $TCPDUMP_PID

echo "=== 8. RUN ML CLASSIFIER ==="
cd /root/ghost-quic-v2/bench
echo "--- GHOST vs HTTP/2 (50 SESSIONS) ---"
python3 ml_tls.py ghost:/root/ghost_final.pcap http2:/root/http2_final.pcap

echo "--- VISION vs HTTP/2 (50 SESSIONS) ---"
python3 ml_tls.py vision:/root/vision_final.pcap http2:/root/http2_final.pcap
