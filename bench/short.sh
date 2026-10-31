#!/bin/bash
# Замер коротких HTTPS-запросов через SOCKS5.
# Использование: short.sh <port> <n> <out_csv>

PORT=$1
N=${2:-20}
OUT=${3:-/tmp/bench_short.csv}

echo "idx,port,http_code,time_total" > "$OUT"

for i in $(seq 1 "$N"); do
  RESULT=$(timeout 15 curl -4 -sS --socks5 127.0.0.1:"$PORT" \
    -o /dev/null \
    -w "%{http_code},%{time_total}" \
    https://example.com 2>&1)
  echo "$i,$PORT,$RESULT" >> "$OUT"
done

echo "done: $OUT"
