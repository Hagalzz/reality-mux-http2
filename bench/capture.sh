#!/bin/bash
# Использование: capture.sh <port> <label> <duration_sec>
PORT=$1
LABEL=$2
DUR=${3:-30}

mkdir -p pcap

# Захват на lo
timeout $DUR tcpdump -i lo -w "pcap/${LABEL}.pcap" \
  "port $PORT or port 9990" 2>/dev/null &
TCPDUMP_PID=$!
sleep 0.5

# Нагрузка через этот порт (100 запросов последовательно)
URL="http://127.0.0.1:9990/small"
./h1bench -socks=127.0.0.1:$PORT -url=$URL -n=50 -warmup=3 -c=1 2>&1 | tail -2

wait $TCPDUMP_PID 2>/dev/null
echo "saved: pcap/${LABEL}.pcap"
ls -la "pcap/${LABEL}.pcap"
