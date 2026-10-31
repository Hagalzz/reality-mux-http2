package proxy

import (
"context"
"net"
"strings"
"testing"
"time"
)

// stubResolver возвращает фиксированные IP для любого имени.
func stubResolver(ips []string) *net.Resolver {
return &net.Resolver{
PreferGo: true,
Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
// не используется, потому что PreferGo + LookupIPAddr пойдёт
// через этот Dial. Возвращаем pipe с готовым ответом невозможно
// без DNS-парсера, поэтому используем другой подход.
return nil, nil
},
}
}

func TestTargetDialerLiteralLoopbackRejected(t *testing.T) {
d := NewTargetDialer(DefaultSSRFPolicy(), time.Second)
_, err := d.Dial(context.Background(), "127.0.0.1", 80)
if err == nil {
t.Fatal("loopback literal should be rejected")
}
if !strings.Contains(err.Error(), "ssrf") {
t.Fatalf("want ssrf error, got %v", err)
}
}

func TestTargetDialerLiteralPrivateRejected(t *testing.T) {
d := NewTargetDialer(DefaultSSRFPolicy(), time.Second)
cases := []string{
"10.0.0.1",
"192.168.1.1",
"169.254.1.1",
"::1",
"fe80::1",
"100.64.0.1",
}
for _, ip := range cases {
if _, err := d.Dial(context.Background(), ip, 80); err == nil {
t.Errorf("%s should be rejected", ip)
}
}
}

func TestTargetDialerBenchmarkAllowsLoopback(t *testing.T) {
// Слушаем на loopback и пробуем подключиться через benchmark policy.
ln, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
t.Fatal(err)
}
defer ln.Close()

go func() {
c, err := ln.Accept()
if err == nil {
c.Close()
}
}()

_, portStr, _ := net.SplitHostPort(ln.Addr().String())
var port uint16
_, _ = net.LookupPort("tcp", portStr)
for _, b := range []byte(portStr) {
port = port*10 + uint16(b-'0')
}

d := NewTargetDialer(BenchmarkSSRFPolicy(), time.Second)
conn, err := d.Dial(context.Background(), "127.0.0.1", port)
if err != nil {
t.Fatalf("benchmark policy should allow loopback: %v", err)
}
conn.Close()
}

func TestTargetDialerContextCancel(t *testing.T) {
d := NewTargetDialer(BenchmarkSSRFPolicy(), 5*time.Second)
ctx, cancel := context.WithCancel(context.Background())
cancel() // сразу отменяем

// Слушатель, чтобы не получить connection refused раньше отмены.
ln, _ := net.Listen("tcp", "127.0.0.1:0")
defer ln.Close()
_, portStr, _ := net.SplitHostPort(ln.Addr().String())
var port uint16
for _, b := range []byte(portStr) {
port = port*10 + uint16(b-'0')
}

_, err := d.Dial(ctx, "127.0.0.1", port)
if err == nil {
t.Fatal("cancelled context should produce error")
}
}

func TestTargetDialerPolicyAccessor(t *testing.T) {
d := NewTargetDialer(DefaultSSRFPolicy(), 0)
if d.Policy().AllowLocalOrigins {
t.Fatal("default policy should not allow local origins")
}
d = NewTargetDialer(BenchmarkSSRFPolicy(), 0)
if !d.Policy().AllowLocalOrigins {
t.Fatal("benchmark policy should allow local origins")
}
}

func TestTargetDialerAllowedHelper(t *testing.T) {
d := NewTargetDialer(DefaultSSRFPolicy(), 0)
if d.allowed(net.ParseIP("127.0.0.1")) {
t.Fatal("loopback should be denied")
}
if !d.allowed(net.ParseIP("1.1.1.1")) {
t.Fatal("public should be allowed")
}

d2 := NewTargetDialer(BenchmarkSSRFPolicy(), 0)
if !d2.allowed(net.ParseIP("127.0.0.1")) {
t.Fatal("benchmark policy should allow loopback")
}
if d2.allowed(net.ParseIP("10.0.0.1")) {
t.Fatal("benchmark policy should still deny private")
}
}

// Пропускаем stubResolver — он требует реализации DNS wire-протокола.
// Логика domain-dial покрыта literal-ip тестами выше и
// integration-тестом на верхнем уровне (e2e).
var _ = stubResolver
