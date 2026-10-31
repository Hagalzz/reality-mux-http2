package proxy

import (
"context"
"fmt"
"net"
"time"
)

// TargetDialer выполняет резолв и dial к целевому адресу,
// применяя SSRF-политику ко ВСЕМ разрешённым IP.
//
// Ключевые правила из брифа и от Sol:
//   - не доверяем одному DNS-ответу;
//   - проверяем реальные выбранные IP;
//   - нормализуем IPv4-mapped IPv6;
//   - домен резолвится здесь, а не в Control (Control видит IP).
type TargetDialer struct {
dialer *Dialer
// resolver — переопределяемый для тестов.
resolver *net.Resolver
// dialTimeout — ограничение на одну попытку.
dialTimeout time.Duration
}

// NewTargetDialer создаёт резолвер с заданной политикой.
func NewTargetDialer(policy SSRFPolicy, dialTimeout time.Duration) *TargetDialer {
if dialTimeout <= 0 {
dialTimeout = 10 * time.Second
}
return &TargetDialer{
dialer:      NewDialer(policy, dialTimeout),
resolver:    net.DefaultResolver,
dialTimeout: dialTimeout,
}
}

// Dial резолвит host и устанавливает соединение с первым
// допустимым IP. При ошибке возвращает ErrAddressDenied,
// если все адреса отклонены политикой.
//
// host может быть:
//   - IPv4-литерал;
//   - IPv6-литерал;
//   - домен.
//
// В v1 IPv6-only fallback не используется: если все A/AAAA
// отфильтрованы — ошибка.
func (t *TargetDialer) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
addr := net.JoinHostPort(host, fmt.Sprint(port))

// Литеральный IP — сразу проверяем.
if ip := net.ParseIP(host); ip != nil {
if !t.allowed(ip) {
return nil, fmt.Errorf("ssrf: literal address %s denied", host)
}
dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
defer cancel()
return t.dialer.DialContext(dialCtx, "tcp", addr)
}

// Резолв.
ips, err := t.resolver.LookupIPAddr(ctx, host)
if err != nil {
return nil, fmt.Errorf("resolve %s: %w", host, err)
}
if len(ips) == 0 {
return nil, fmt.Errorf("resolve %s: no addresses", host)
}

// Фильтруем: только разрешённые.
var allowed []net.IP
for _, a := range ips {
if t.allowed(a.IP) {
allowed = append(allowed, a.IP)
}
}
if len(allowed) == 0 {
return nil, fmt.Errorf("ssrf: all %d addresses for %s denied", len(ips), host)
}

// Пытаемся по очереди. Первый успешный — побеждает.
var lastErr error
for _, ip := range allowed {
select {
case <-ctx.Done():
return nil, ctx.Err()
default:
}

ipAddr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
conn, err := t.dialer.DialContext(dialCtx, "tcp", ipAddr)
cancel()
if err == nil {
return conn, nil
}
lastErr = err
}
return nil, fmt.Errorf("dial %s: %w", host, lastErr)
}

// allowed — обёртка над политикой.
func (t *TargetDialer) allowed(ip net.IP) bool {
if t.dialer.policy.AllowLocalOrigins && ip.IsLoopback() {
return true
}
return IsPublicIP(ip)
}

// Policy возвращает текущую политику. Для тестов.
func (t *TargetDialer) Policy() SSRFPolicy {
return t.dialer.policy
}

// SetResolver — для тестов.
func (t *TargetDialer) SetResolver(r *net.Resolver) {
if r != nil {
t.resolver = r
}
}

// DialContext реализует интерфейс, ожидаемый reality.Config.DialContext:
//   func(ctx, network, address) (net.Conn, error)
//
// Использует тот же SSRF-фильтр, что и Dial, но принимает
// address в формате "host:port" (host — уже IP, DNS резолвит ядро).
func (t *TargetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
return t.dialer.DialContext(ctx, network, address)
}
