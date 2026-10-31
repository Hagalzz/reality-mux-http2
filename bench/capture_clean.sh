#!/bin/bash
# capture_clean.sh <port> <label>
# Захватывает всё на lo (весь трафик, чтобы увидеть пары), 30 сек.

PORT=$1
LABEL=$2
DUR=30

mkdir -p pcap

echo "[capture] starting for port $PORT, label=$LABEL, duration=${DUR}s"
timeout $DUR tcpdump -i lo -w "pcap/${LABEL}.pcap" 'tcp' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

echo "[capture] running workload..."
URL="http://127.0.0.1:9990/small"
./h1bench -socks=127.0.0.1:$PORT -url=$URL -n=100 -warmup=5 -c=8 2>&1 | grep req/sec

echo "[capture] waiting for tcpdump..."
wait $TCPDUMP_PID 2>/dev/null

SIZE=$(ls -la "pcap/${LABEL}.pcap" | awk '{print $5}')
echo "[capture] saved: pcap/${LABEL}.pcap size=${SIZE}B"

# Быстрая статистика
echo "[capture] packet count:"
tcpdump -r "pcap/${LABEL}.pcap" 2>/dev/null | wc -l
