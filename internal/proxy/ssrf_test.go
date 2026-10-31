package proxy

import (
"net"
"testing"
)

func TestIsPublicIPRejectsNonPublic(t *testing.T) {
bad := []string{
"127.0.0.1",
"127.1.2.3",
"0.0.0.0",
"::",
"::1",
"10.0.0.1",
"10.255.255.255",
"172.16.0.1",
"172.31.255.255",
"192.168.0.1",
"192.168.255.255",
"169.254.1.1",
"fe80::1",
"fc00::1",
"fd00::1",
"224.0.0.1",
"ff00::1",
"100.64.0.1",
"100.127.255.255",
"::ffff:127.0.0.1", // IPv4-mapped loopback
}
for _, s := range bad {
ip := net.ParseIP(s)
if ip == nil {
t.Fatalf("bad test IP: %s", s)
}
if IsPublicIP(ip) {
t.Errorf("IsPublicIP(%s) = true, want false", s)
}
}
}

func TestIsPublicIPAcceptsPublic(t *testing.T) {
good := []string{
"1.1.1.1",
"8.8.8.8",
"89.160.20.128", // условный шведский
"2001:4860:4860::8888",
"2606:4700:4700::1111",
"9.9.9.9",
}
for _, s := range good {
ip := net.ParseIP(s)
if ip == nil {
t.Fatalf("bad test IP: %s", s)
}
if !IsPublicIP(ip) {
t.Errorf("IsPublicIP(%s) = false, want true", s)
}
}
}

func TestIsPublicIPNil(t *testing.T) {
if IsPublicIP(nil) {
t.Fatal("IsPublicIP(nil) should be false")
}
}

func TestIsPublicAddrIPv4(t *testing.T) {
pub := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
if !IsPublicAddr(pub) {
t.Fatal("public addr should pass")
}

loop := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}
if IsPublicAddr(loop) {
t.Fatal("loopback should fail")
}
}

func TestIsPublicAddrWrongType(t *testing.T) {
// net.Addr не *net.TCPAddr
if IsPublicAddr(nil) {
t.Fatal("nil addr should be false")
}
}

func TestDialerRejectsLoopbackByDefault(t *testing.T) {
d := NewDialer(DefaultSSRFPolicy(), 0)
// Проверяем сам control через имитацию.
err := d.control("tcp", "127.0.0.1:8080", nil)
if err == nil {
t.Fatal("loopback should be rejected by default policy")
}
}

func TestDialerRejectsPrivate(t *testing.T) {
d := NewDialer(DefaultSSRFPolicy(), 0)
cases := []string{
"10.0.0.1:80",
"192.168.1.1:80",
"172.16.0.1:80",
"169.254.1.1:80",
"[fe80::1]:80",
}
for _, c := range cases {
if err := d.control("tcp", c, nil); err == nil {
t.Errorf("%s should be rejected", c)
}
}
}

func TestDialerAcceptsPublic(t *testing.T) {
d := NewDialer(DefaultSSRFPolicy(), 0)
if err := d.control("tcp", "1.1.1.1:443", nil); err != nil {
t.Fatalf("public IP should be accepted: %v", err)
}
}

func TestDialerBenchmarkPolicyAllowsLoopback(t *testing.T) {
d := NewDialer(BenchmarkSSRFPolicy(), 0)
if err := d.control("tcp", "127.0.0.1:9990", nil); err != nil {
t.Fatalf("benchmark policy should allow loopback: %v", err)
}
// private всё равно запрещён
if err := d.control("tcp", "192.168.1.1:80", nil); err == nil {
t.Fatal("benchmark policy should not allow private")
}
}

func TestDialerRejectsBadAddress(t *testing.T) {
d := NewDialer(DefaultSSRFPolicy(), 0)
if err := d.control("tcp", "not-an-address", nil); err == nil {
t.Fatal("bad address should error")
}
}

func TestDialerRejectsNonIPHost(t *testing.T) {
d := NewDialer(DefaultSSRFPolicy(), 0)
// Домен вместо IP — control должен отклонить.
// Резолв делается ядром до control; в v1 мы ожидаем numeric IP.
if err := d.control("tcp", "example.com:80", nil); err == nil {
t.Fatal("non-IP host should error in control")
}
}
