#!/bin/bash
pkill -f ghost-server; pkill -f ghost-client; pkill -f xray-test; pkill -f origin; pkill -f http2_tls
pkill -f tshark
sleep 1

rm -f /tmp/ghost_small.pcap /tmp/vision_small.pcap /tmp/http2_small.pcap

setsid /tmp/origin > /dev/null 2>&1 < /dev/null &
setsid /root/http2_tls > /dev/null 2>&1 < /dev/null &
sleep 2

cd /root/ghost-quic-v2
# Xray Vision
setsid /tmp/xray-test -c /tmp/xray-server-A.json > /dev/null 2>&1 < /dev/null &
sleep 1
setsid /tmp/xray-test -c /tmp/xray-client-A.json > /dev/null 2>&1 < /dev/null &
sleep 2

# Ghost Frag
PRIV=$(grep '^PRIVATE=' secrets/reality_private.txt | cut -d= -f2)
PUB=$(grep '^PUBLIC=' secrets/reality_private.txt | cut -d= -f2)
setsid env REALITY_PRIVATE=$PRIV REALITY_DEST=www.microsoft.com:443 /tmp/ghost-server-8k > /tmp/server.log 2>&1 < /dev/null &
for i in {1..10}; do ss -tln | grep -q 9449 && break; sleep 1; done

echo "=== CAPTURE GHOST (50 sessions, medium) ==="
tshark -l -B 100 -i lo -f "tcp port 9449" -w /tmp/ghost_small.pcap > /dev/null 2>&1 &
TSHARK_PID=$!
sleep 1
for i in {1..50}; do
    pkill -f ghost-client; sleep 0.5
    setsid env REALITY_PUBLIC=$PUB REALITY_ADDR=127.0.0.1:9449 /tmp/ghost-client-8k -socks=127.0.0.1:1085 > /dev/null 2>&1 < /dev/null &
    sleep 1.0
    curl -s --socks5 127.0.0.1:1085 http://127.0.0.1:9990/medium -o /dev/null; sleep 0.5
done
sleep 1
kill -INT $TSHARK_PID
sleep 1; pkill -f ghost-client

echo "=== CAPTURE VISION (50 sessions, medium) ==="
tshark -l -B 100 -i lo -f "tcp port 9445" -w /tmp/vision_small.pcap > /dev/null 2>&1 &
TSHARK_PID=$!
sleep 1
for i in {1..50}; do curl -s --socks5 127.0.0.1:1081 http://127.0.0.1:9990/medium -o /dev/null; sleep 0.5; done
sleep 1
kill -INT $TSHARK_PID
sleep 1

echo "=== CAPTURE HTTP/2 (50 sessions, medium) ==="
tshark -l -B 100 -i lo -f "tcp port 8444" -w /tmp/http2_small.pcap > /dev/null 2>&1 &
TSHARK_PID=$!
sleep 1
for i in {1..50}; do curl -k -s --http2 https://127.0.0.1:8444/ -o /dev/null; sleep 0.5; done
sleep 1
kill -INT $TSHARK_PID
sleep 1

echo "=== PCAP SIZES ==="
ls -la /tmp/*_small.pcap

echo "=== ML RESULTS ==="
cd /root/ghost-quic-v2/bench
echo "--- 1. GHOST (FRAG) vs HTTP/2 ---"
python3 ml_tls.py ghost:/tmp/ghost_small.pcap http2:/tmp/http2_small.pcap

echo "--- 2. VISION vs HTTP/2 ---"
python3 ml_tls.py vision:/tmp/vision_small.pcap http2:/tmp/http2_small.pcap

echo "--- 3. GHOST (FRAG) vs VISION ---"
python3 ml_tls.py ghost:/tmp/ghost_small.pcap vision:/tmp/vision_small.pcap
