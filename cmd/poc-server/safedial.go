package main

import (
"context"
"errors"
"fmt"
"net"
"net/netip"
	"os"
"syscall"
)

// safeDialContext сохраняет Happy Eyeballs и кэш DNS,
// но проверяет resolved IP через Dialer.Control.
// Непубличные адреса отклоняются до connect.
func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
d := &net.Dialer{
Control: func(network, address string, c syscall.RawConn) error {
host, _, err := net.SplitHostPort(address)
if err != nil {
return err
}
ip, err := netip.ParseAddr(host)
if err != nil {
return fmt.Errorf("parse addr %q: %w", host, err)
}
if !isPublicIP(ip) {
// ONLY FOR TEST STAND: allow private IPs when env set.
// In production this env is never set.
if os.Getenv("REALITY_ALLOW_PRIVATE") == "1" {
return nil
}
return errors.New("non-public address rejected: " + ip.String())
}
return nil
},
}
return d.DialContext(ctx, network, address)
}

// isPublicIP возвращает true только для глобально маршрутизируемых адресов.
func isPublicIP(ip netip.Addr) bool {
if !ip.IsValid() {
return false
}
if ip.Is4In6() {
ip = ip.Unmap()
}
if ip.Zone() != "" {
return false
}
if ip.IsLoopback() ||
ip.IsPrivate() ||
ip.IsLinkLocalUnicast() ||
ip.IsLinkLocalMulticast() ||
ip.IsInterfaceLocalMulticast() ||
ip.IsMulticast() ||
ip.IsUnspecified() {
return false
}
if ip.Is4() {
b := ip.As4()
if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // CGNAT
return false
}
if b[0] == 198 && (b[1] == 18 || b[1] == 19) { // benchmark
return false
}
if b[0] == 192 && b[1] == 0 && b[2] == 2 { // doc
return false
}
if b[0] == 198 && b[1] == 51 && b[2] == 100 { // doc
return false
}
if b[0] == 203 && b[1] == 0 && b[2] == 113 { // doc
return false
}
if b[0] >= 240 { // reserved
return false
}
}
if ip.Is6() {
b := ip.As16()
if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { // doc
return false
}
}
return true
}
