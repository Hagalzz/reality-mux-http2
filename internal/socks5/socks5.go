// Package socks5 реализует минимальный серверный парсер
// SOCKS5 CONNECT для GHOST mux.
//
// Поддержка v1:
//   - версия 0x05;
//   - метод аутентификации 0x00 (no-auth);
//   - команда CONNECT (0x01);
//   - ATYP: IPv4 (0x01), domain (0x03), IPv6 (0x04).
//
// Не поддерживается:
//   - BIND, UDP ASSOCIATE;
//   - GSSAPI, user/pass auth.
package socks5

import (
"encoding/binary"
"errors"
"fmt"
"io"
"net"
"strconv"
)

// Версия протокола.
const Version = 0x05

// Методы аутентификации.
const (
MethodNoAuth       = 0x00
MethodUserPass     = 0x02
MethodNoAcceptable = 0xFF
)

// Команды.
const (
CmdConnect = 0x01
CmdBind    = 0x02
CmdUDP     = 0x03
)

// Типы адресов.
const (
AtypIPv4   = 0x01
AtypDomain = 0x03
AtypIPv6   = 0x04
)

// Коды ответа (reply field).
const (
RepSuccess              = 0x00
RepGeneralFailure       = 0x01
RepNotAllowed           = 0x02
RepNetworkUnreachable   = 0x03
RepHostUnreachable      = 0x04
RepConnectionRefused    = 0x05
RepTTLExpired           = 0x06
RepCommandNotSupported  = 0x07
RepAddressNotSupported  = 0x08
)

// ErrNoAcceptableMethod — клиент не предложил no-auth.
var ErrNoAcceptableMethod = errors.New("socks5: no acceptable auth method")

// ErrUnsupportedCommand — BIND или UDP ASSOCIATE.
var ErrUnsupportedCommand = errors.New("socks5: unsupported command")

// ErrUnsupportedAddress — неизвестный ATYP.
var ErrUnsupportedAddress = errors.New("socks5: unsupported address type")

// Request — разобранный CONNECT.
type Request struct {
	Cmd byte
// Host — целевой адрес (IP или домен).
Host string
// Port — целевой порт.
Port uint16
// RawAddr — исходное представление адреса в том виде, в котором
// его нужно передавать в GHOST OPEN.
RawAddr []byte
}

// Addr возвращает host:port в формате net.JoinHostPort.
func (r *Request) Addr() string {
return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// Negotiate выполняет SOCKS5 negotiation: version + method.
//
// Читает от client, отвечает на writer. Только no-auth.
// Возвращает ошибку, если клиент не предложил no-auth или
// версия не 0x05.
func Negotiate(client io.Reader, server io.Writer) error {
var hdr [2]byte
if _, err := io.ReadFull(client, hdr[:]); err != nil {
return fmt.Errorf("socks5: read version: %w", err)
}
if hdr[0] != Version {
return fmt.Errorf("socks5: unsupported version 0x%02x", hdr[0])
}
n := int(hdr[1])
if n == 0 {
// отправим FF и выйдем
_, _ = server.Write([]byte{Version, MethodNoAcceptable})
return ErrNoAcceptableMethod
}

methods := make([]byte, n)
if _, err := io.ReadFull(client, methods); err != nil {
return fmt.Errorf("socks5: read methods: %w", err)
}

found := false
for _, m := range methods {
if m == MethodNoAuth {
found = true
break
}
}
if !found {
_, _ = server.Write([]byte{Version, MethodNoAcceptable})
return ErrNoAcceptableMethod
}

if _, err := server.Write([]byte{Version, MethodNoAuth}); err != nil {
return fmt.Errorf("socks5: write method reply: %w", err)
}
return nil
}

// ReadRequest читает SOCKS5 CONNECT request.
//
// Вызывается после успешного Negotiate. Парсит version, cmd, atyp,
// addr, port. Возвращает ErrUnsupportedCommand для BIND/UDP и
// ErrUnsupportedAddress для неизвестного atyp.
//
// RawAddr — это байты addr в том виде, как их нужно передать в GHOST OPEN:
//   - IPv4: 4 байта
//   - IPv6: 16 байт
//   - domain: len-prefixed, 1 + n байт
func ReadRequest(client io.Reader) (*Request, error) {
var hdr [4]byte
if _, err := io.ReadFull(client, hdr[:]); err != nil {
return nil, fmt.Errorf("socks5: read request header: %w", err)
}
if hdr[0] != Version {
return nil, fmt.Errorf("socks5: request version 0x%02x", hdr[0])
}
cmd := hdr[1]
	if cmd != CmdConnect && cmd != CmdUDP {
return nil, fmt.Errorf("%w: cmd 0x%02x", ErrUnsupportedCommand, cmd)
}
// hdr[2] = reserved, должен быть 0x00, но многие клиенты
// игнорируют; не проверяем жёстко.

req := &Request{Cmd: cmd}

switch hdr[3] {
case AtypIPv4:
buf := make([]byte, 4)
if _, err := io.ReadFull(client, buf); err != nil {
return nil, fmt.Errorf("socks5: read ipv4: %w", err)
}
req.Host = net.IP(buf).String()
req.RawAddr = append([]byte{AtypIPv4}, buf...)

case AtypIPv6:
buf := make([]byte, 16)
if _, err := io.ReadFull(client, buf); err != nil {
return nil, fmt.Errorf("socks5: read ipv6: %w", err)
}
req.Host = net.IP(buf).String()
req.RawAddr = append([]byte{AtypIPv6}, buf...)

case AtypDomain:
var l [1]byte
if _, err := io.ReadFull(client, l[:]); err != nil {
return nil, fmt.Errorf("socks5: read domain len: %w", err)
}
if l[0] == 0 {
return nil, errors.New("socks5: empty domain")
}
buf := make([]byte, l[0])
if _, err := io.ReadFull(client, buf); err != nil {
return nil, fmt.Errorf("socks5: read domain: %w", err)
}
req.Host = string(buf)
req.RawAddr = append([]byte{AtypDomain, l[0]}, buf...)

default:
return nil, fmt.Errorf("%w: atyp 0x%02x", ErrUnsupportedAddress, hdr[3])
}

var port [2]byte
if _, err := io.ReadFull(client, port[:]); err != nil {
return nil, fmt.Errorf("socks5: read port: %w", err)
}
req.Port = binary.BigEndian.Uint16(port[:])
return req, nil
}

// WriteReply отправляет SOCKS5 reply.
//
// rep — код ответа. bindAddr — адрес, который мы якобы привязали
// (обычно 0.0.0.0:0 для CONNECT).
func WriteReply(server io.Writer, rep byte, bindAddr net.Addr) error {
resp := []byte{Version, rep, 0x00}

if bindAddr == nil {
// 0.0.0.0:0
resp = append(resp, AtypIPv4, 0, 0, 0, 0, 0, 0)
return writeFull(server, resp)
}

host, portStr, err := net.SplitHostPort(bindAddr.String())
if err != nil {
resp = append(resp, AtypIPv4, 0, 0, 0, 0, 0, 0)
return writeFull(server, resp)
}
port, _ := strconv.Atoi(portStr)

if ip := net.ParseIP(host); ip != nil {
if v4 := ip.To4(); v4 != nil {
resp = append(resp, AtypIPv4)
resp = append(resp, v4...)
} else {
resp = append(resp, AtypIPv6)
resp = append(resp, ip.To16()...)
}
} else {
if len(host) > 255 {
host = host[:255]
}
resp = append(resp, AtypDomain, byte(len(host)))
resp = append(resp, host...)
}
resp = append(resp, byte(port>>8), byte(port))
return writeFull(server, resp)
}

// writeFull — обёртка, возвращающая осмысленную ошибку.
func writeFull(w io.Writer, b []byte) error {
_, err := w.Write(b)
return err
}
