package proxy

import (
"context"
"fmt"
"net"
"syscall"
"time"
)

// SSRFPolicy определяет, какие адреса разрешены для outbound dial.
type SSRFPolicy struct {
// AllowLocalOrigins разрешает loopback для локального benchmark
// (origin на 127.0.0.1:9990). В проде — false.
AllowLocalOrigins bool
}

// DefaultSSRFPolicy — production-политика без исключений.
func DefaultSSRFPolicy() SSRFPolicy {
return SSRFPolicy{AllowLocalOrigins: false}
}

// BenchmarkSSRFPolicy разрешает loopback для origin 127.0.0.1.
// Использовать ТОЛЬКО для локальных замеров.
func BenchmarkSSRFPolicy() SSRFPolicy {
return SSRFPolicy{AllowLocalOrigins: true}
}

// IsPublicIP возвращает true для глобально маршрутизируемых IP.
//
// Отклоняет:
//   - nil
//   - loopback (127.0.0.0/8, ::1)
//   - private (10/8, 172.16/12, 192.168/16, fc00::/7)
//   - link-local (169.254/16, fe80::/10)
//   - multicast
//   - unspecified (0.0.0.0, ::)
//   - carrier-grade NAT (100.64/10)
//   - IPv4-mapped IPv6 приводятся к IPv4 и проверяются отдельно
func IsPublicIP(ip net.IP) bool {
if ip == nil {
return false
}
if v4 := ip.To4(); v4 != nil {
ip = v4
}

if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
ip.IsInterfaceLocalMulticast() || ip.IsPrivate() {
return false
}

// CGNAT 100.64.0.0/10
if v4 := ip.To4(); v4 != nil {
if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
return false
}
}
return true
}

// IsPublicAddr проверяет net.Addr (обычно *net.TCPAddr).
func IsPublicAddr(a net.Addr) bool {
tcp, ok := a.(*net.TCPAddr)
if !ok {
return false
}
return IsPublicIP(tcp.IP)
}

// Dialer — dialer с SSRF-защитой.
//
// Happy Eyeballs сохраняется: Control применяется к каждой
// попытке connect, но не мешает перебору адресов.
type Dialer struct {
policy SSRFPolicy
dialer *net.Dialer
}

// NewDialer создаёт Dialer с заданной политикой и таймаутом.
func NewDialer(policy SSRFPolicy, timeout time.Duration) *Dialer {
if timeout <= 0 {
timeout = 10 * time.Second
}
d := &Dialer{policy: policy}
d.dialer = &net.Dialer{
Timeout:   timeout,
KeepAlive: 30 * time.Second,
Control:   d.control,
}
return d
}

// control вызывается ядром перед connect для каждого адреса.
func (d *Dialer) control(network, address string, c syscall.RawConn) error {
host, _, err := net.SplitHostPort(address)
if err != nil {
return fmt.Errorf("ssrf: bad address %q: %w", address, err)
}
ip := net.ParseIP(host)
if ip == nil {
return fmt.Errorf("ssrf: expected IP, got %q", host)
}

if d.policy.AllowLocalOrigins && ip.IsLoopback() {
return nil
}
if !IsPublicIP(ip) {
return fmt.Errorf("ssrf: address %s not allowed", ip)
}
return nil
}

// DialContext устанавливает TCP-соединение с проверкой адреса.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
return d.dialer.DialContext(ctx, network, address)
}

// Policy возвращает текущую политику. Для тестов и диагностики.
func (d *Dialer) Policy() SSRFPolicy {
return d.policy
}
