package main

import (
"context"
"flag"
"fmt"
"io"
"log"
"net"
"net/http"
"net/url"
"os"
"sort"
"sync"
"sync/atomic"
"time"

"golang.org/x/net/proxy"
)

var (
socksAddr = flag.String("socks", "127.0.0.1:1081", "SOCKS5 address")
target    = flag.String("url", "http://127.0.0.1:9990/small", "target URL")
n         = flag.Int("n", 100, "total number of requests")
warmup    = flag.Int("warmup", 5, "warmup requests")
conc      = flag.Int("c", 1, "concurrency (parallel workers)")
)

type connCounter struct {
total int64
}

func (c *connCounter) inc() {
atomic.AddInt64(&c.total, 1)
}

func (c *connCounter) get() int {
return int(atomic.LoadInt64(&c.total))
}

func main() {
flag.Parse()

socksURL, _ := url.Parse("socks5://" + *socksAddr)
baseDialer, err := proxy.FromURL(socksURL, proxy.Direct)
if err != nil {
log.Fatal(err)
}

cc := &connCounter{}
wrappedDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
cc.inc()
return baseDialer.Dial(network, addr)
}

// MaxConnsPerHost = concurrency
tr := &http.Transport{
DialContext:           wrappedDial,
MaxConnsPerHost:       *conc,
MaxIdleConnsPerHost:   *conc,
DisableKeepAlives:     false,
IdleConnTimeout:       60 * time.Second,
ResponseHeaderTimeout: 30 * time.Second,
}

client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

// Warmup
for i := 0; i < *warmup; i++ {
resp, err := client.Get(*target)
if err != nil {
log.Fatalf("warmup %d: %v", i, err)
}
io.Copy(io.Discard, resp.Body)
resp.Body.Close()
}

// Замер с concurrency
times := make([]float64, *n)
var wg sync.WaitGroup
sem := make(chan struct{}, *conc)
idx := int64(0)

start := time.Now()
for w := 0; w < *conc; w++ {
wg.Add(1)
go func() {
defer wg.Done()
for {
i := atomic.AddInt64(&idx, 1) - 1
if i >= int64(*n) {
return
}
sem <- struct{}{}
t0 := time.Now()
resp, err := client.Get(*target)
if err != nil {
log.Printf("req %d: %v", i, err)
<-sem
continue
}
io.Copy(io.Discard, resp.Body)
resp.Body.Close()
times[i] = time.Since(t0).Seconds()
<-sem
}
}()
}
wg.Wait()
total := time.Since(start).Seconds()

sort.Float64s(times)
mean := 0.0
for _, t := range times {
mean += t
}
mean /= float64(len(times))

p50 := times[len(times)/2]
p95 := times[int(float64(len(times))*0.95)]
p99 := times[int(float64(len(times))*0.99)]

fmt.Fprintf(os.Stderr, "socks=%s c=%d n=%d url=%s\n", *socksAddr, *conc, *n, *target)
fmt.Fprintf(os.Stderr, "req/sec=%.1f mean=%.4f p50=%.4f p95=%.4f p99=%.4f tcp_conn=%d\n",
float64(*n)/total, mean, p50, p95, p99, cc.get())
}
