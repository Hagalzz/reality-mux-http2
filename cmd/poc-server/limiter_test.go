package main

import (
"testing"
)

func TestMaxActive(t *testing.T) {
l := NewLimiter()

// Заполняем max_active, используя разные IP, чтобы обойти per-IP rate.
// Каждый IP даёт burst=8, нужно 8 IP для 64 коннектов.
allowed := 0
for i := 0; i < 200; i++ {
ip := "10.0." + itoa(i/8+1) + "." + itoa(i%8+1)
if l.Allow(ip + ":12345") {
allowed++
}
}
if allowed != maxActiveConns {
t.Fatalf("allowed %d, want %d", allowed, maxActiveConns)
}
t.Logf("max active: allowed %d, blocked %d", allowed, 200-allowed)

// Проверяем 65-й: должен быть отклонён даже с новым IP
if l.Allow("10.0.99.99:12345") {
t.Fatal("65th connection should be rejected by max_active")
}

// Done освобождает слот
l.Done("10.0.1.1:12345")
if !l.Allow("10.0.99.99:12345") {
t.Fatal("after Done, new connection should be allowed")
}
t.Log("after Done: new connection allowed")
}

func TestPerIPRate(t *testing.T) {
l := NewLimiter()

// Burst = 8, потом rate = 2/сек
allowed := 0
for i := 0; i < 20; i++ {
if l.Allow("10.0.0.1:12345") {
allowed++
}
}
if allowed != perIPRateBurst {
t.Fatalf("per-IP burst: allowed %d, want %d", allowed, perIPRateBurst)
}
t.Logf("per-IP burst: allowed %d, blocked %d", allowed, 20-allowed)
}

func TestIPKeyIgnoresPort(t *testing.T) {
l := NewLimiter()

// Разные порты одного IP должны делить один bucket
for i := 0; i < perIPRateBurst; i++ {
if !l.Allow("10.0.0.1:" + itoa(10000+i)) {
t.Fatalf("connection %d should be allowed", i)
}
}
// 9-й с другим портом должен быть отклонён
if l.Allow("10.0.0.1:99999") {
t.Fatal("port change should not bypass rate limit")
}
t.Log("port change correctly ignored")
}

func itoa(i int) string {
if i == 0 {
return "0"
}
var buf [12]byte
pos := len(buf)
for i > 0 {
pos--
buf[pos] = byte('0' + i%10)
i /= 10
}
return string(buf[pos:])
}
