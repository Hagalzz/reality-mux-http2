package main

import (
"net"
"sync"
"time"
)

const (
maxActiveConns  = 64
perIPRateLimit  = 2.0
perIPRateBurst  = 8
limiterCleanup  = 5 * time.Minute
limiterEntryTTL = 10 * time.Minute
)

type ipBucket struct {
tokens   float64
lastFill time.Time
lastSeen time.Time
}

type Limiter struct {
mu      sync.Mutex
active  int
byIP    map[string]*ipBucket
}

func NewLimiter() *Limiter {
l := &Limiter{byIP: make(map[string]*ipBucket)}
go l.cleanupLoop()
return l
}

// Allow проверяет оба лимита и увеличивает счётчик active.
// Возвращает false, если соединение отклонено.
func (l *Limiter) Allow(remoteAddr string) bool {
ip := ipOf(remoteAddr)

l.mu.Lock()
defer l.mu.Unlock()

if l.active >= maxActiveConns {
return false
}

now := time.Now()
b, ok := l.byIP[ip]
if !ok {
b = &ipBucket{tokens: perIPRateBurst, lastFill: now}
l.byIP[ip] = b
}
// пополняем токены
elapsed := now.Sub(b.lastFill).Seconds()
b.tokens += elapsed * perIPRateLimit
if b.tokens > perIPRateBurst {
b.tokens = perIPRateBurst
}
b.lastFill = now
b.lastSeen = now

if b.tokens < 1.0 {
return false
}
b.tokens -= 1.0
l.active++
return true
}

// Done уменьшает счётчик active. Вызывается при закрытии соединения.
func (l *Limiter) Done(remoteAddr string) {
ip := ipOf(remoteAddr)
l.mu.Lock()
defer l.mu.Unlock()
if l.active > 0 {
l.active--
}
if b, ok := l.byIP[ip]; ok {
b.lastSeen = time.Now()
}
}

func (l *Limiter) cleanupLoop() {
t := time.NewTicker(limiterCleanup)
defer t.Stop()
for range t.C {
cutoff := time.Now().Add(-limiterEntryTTL)
l.mu.Lock()
for ip, b := range l.byIP {
if b.lastSeen.Before(cutoff) {
delete(l.byIP, ip)
}
}
l.mu.Unlock()
}
}

func ipOf(remoteAddr string) string {
host, _, err := net.SplitHostPort(remoteAddr)
if err != nil {
return remoteAddr
}
return host
}
