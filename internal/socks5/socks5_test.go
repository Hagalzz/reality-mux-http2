package socks5

import (
"bytes"
"encoding/binary"
"errors"
"io"
"net"
"strings"
"testing"
)

func TestNegotiateHappyPath(t *testing.T) {
client := bytes.NewBuffer([]byte{Version, 2, MethodNoAuth, MethodUserPass})
var server bytes.Buffer

if err := Negotiate(client, &server); err != nil {
t.Fatalf("Negotiate: %v", err)
}
want := []byte{Version, MethodNoAuth}
if !bytes.Equal(server.Bytes(), want) {
t.Fatalf("server reply = %v, want %v", server.Bytes(), want)
}
}

func TestNegotiateRejectsBadVersion(t *testing.T) {
client := bytes.NewBuffer([]byte{0x04, 1, MethodNoAuth})
var server bytes.Buffer

if err := Negotiate(client, &server); err == nil {
t.Fatal("Negotiate with version 0x04 should error")
}
}

func TestNegotiateNoAcceptableMethod(t *testing.T) {
client := bytes.NewBuffer([]byte{Version, 1, MethodUserPass})
var server bytes.Buffer

err := Negotiate(client, &server)
if !errors.Is(err, ErrNoAcceptableMethod) {
t.Fatalf("want ErrNoAcceptableMethod, got %v", err)
}
if server.Len() != 2 || server.Bytes()[1] != MethodNoAcceptable {
t.Fatalf("server should reply 0xFF, got %v", server.Bytes())
}
}

func TestNegotiateZeroMethods(t *testing.T) {
client := bytes.NewBuffer([]byte{Version, 0})
var server bytes.Buffer

err := Negotiate(client, &server)
if !errors.Is(err, ErrNoAcceptableMethod) {
t.Fatalf("want ErrNoAcceptableMethod, got %v", err)
}
}

func TestReadRequestIPv4(t *testing.T) {
// version, cmd, rsv, atyp, ip, port
raw := []byte{Version, CmdConnect, 0x00, AtypIPv4, 127, 0, 0, 1, 0x1F, 0x90} // 127.0.0.1:8080
req, err := ReadRequest(bytes.NewReader(raw))
if err != nil {
t.Fatalf("ReadRequest: %v", err)
}
if req.Host != "127.0.0.1" {
t.Fatalf("Host = %q, want 127.0.0.1", req.Host)
}
if req.Port != 8080 {
t.Fatalf("Port = %d, want 8080", req.Port)
}
if req.Addr() != "127.0.0.1:8080" {
t.Fatalf("Addr = %q", req.Addr())
}
want := []byte{AtypIPv4, 127, 0, 0, 1}
if !bytes.Equal(req.RawAddr, want) {
t.Fatalf("RawAddr = %v, want %v", req.RawAddr, want)
}
}

func TestReadRequestIPv6(t *testing.T) {
ip := net.ParseIP("2001:db8::1").To16()
raw := []byte{Version, CmdConnect, 0x00, AtypIPv6}
raw = append(raw, ip...)
raw = append(raw, 0x01, 0xBB) // port 443

req, err := ReadRequest(bytes.NewReader(raw))
if err != nil {
t.Fatalf("ReadRequest: %v", err)
}
if req.Host != "2001:db8::1" {
t.Fatalf("Host = %q, want 2001:db8::1", req.Host)
}
if req.Port != 443 {
t.Fatalf("Port = %d, want 443", req.Port)
}
}

func TestReadRequestDomain(t *testing.T) {
domain := "example.com"
raw := []byte{Version, CmdConnect, 0x00, AtypDomain, byte(len(domain))}
raw = append(raw, []byte(domain)...)
raw = append(raw, 0x00, 0x50) // port 80

req, err := ReadRequest(bytes.NewReader(raw))
if err != nil {
t.Fatalf("ReadRequest: %v", err)
}
if req.Host != domain {
t.Fatalf("Host = %q, want %q", req.Host, domain)
}
if req.Port != 80 {
t.Fatalf("Port = %d, want 80", req.Port)
}
}

func TestReadRequestRejectsBind(t *testing.T) {
raw := []byte{Version, CmdBind, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if !errors.Is(err, ErrUnsupportedCommand) {
t.Fatalf("want ErrUnsupportedCommand, got %v", err)
}
}

func TestReadRequestRejectsUDP(t *testing.T) {
raw := []byte{Version, CmdUDP, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if !errors.Is(err, ErrUnsupportedCommand) {
t.Fatalf("want ErrUnsupportedCommand, got %v", err)
}
}

func TestReadRequestRejectsBadAtyp(t *testing.T) {
raw := []byte{Version, CmdConnect, 0x00, 0x99, 0, 0, 0, 0, 0, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if !errors.Is(err, ErrUnsupportedAddress) {
t.Fatalf("want ErrUnsupportedAddress, got %v", err)
}
}

func TestReadRequestRejectsBadVersion(t *testing.T) {
raw := []byte{0x04, CmdConnect, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if err == nil {
t.Fatal("bad version should error")
}
}

func TestReadRequestTruncatedHeader(t *testing.T) {
raw := []byte{Version, CmdConnect}
_, err := ReadRequest(bytes.NewReader(raw))
if err == nil {
t.Fatal("truncated header should error")
}
}

func TestReadRequestTruncatedAddr(t *testing.T) {
raw := []byte{Version, CmdConnect, 0x00, AtypIPv4, 127, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if !errors.Is(err, io.ErrUnexpectedEOF) && err == nil {
t.Fatalf("truncated addr should error, got %v", err)
}
}

func TestReadRequestEmptyDomain(t *testing.T) {
raw := []byte{Version, CmdConnect, 0x00, AtypDomain, 0x00, 0, 0}
_, err := ReadRequest(bytes.NewReader(raw))
if err == nil {
t.Fatal("empty domain should error")
}
}

func TestWriteReplyIPv4(t *testing.T) {
var buf bytes.Buffer
addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
if err := WriteReply(&buf, RepSuccess, addr); err != nil {
t.Fatalf("WriteReply: %v", err)
}
got := buf.Bytes()
if got[0] != Version || got[1] != RepSuccess || got[3] != AtypIPv4 {
t.Fatalf("bad reply header: %v", got[:4])
}
if binary.BigEndian.Uint16(got[8:10]) != 1080 {
t.Fatalf("bad port: %d", binary.BigEndian.Uint16(got[8:10]))
}
}

func TestWriteReplyNilAddr(t *testing.T) {
var buf bytes.Buffer
if err := WriteReply(&buf, RepGeneralFailure, nil); err != nil {
t.Fatalf("WriteReply: %v", err)
}
got := buf.Bytes()
if got[1] != RepGeneralFailure {
t.Fatalf("reply code = %d", got[1])
}
if !bytes.Equal(got[4:8], []byte{0, 0, 0, 0}) {
t.Fatalf("bind addr should be 0.0.0.0, got %v", got[4:8])
}
}

func TestRequestAddr(t *testing.T) {
req := &Request{Host: "example.com", Port: 443}
if got := req.Addr(); got != "example.com:443" {
t.Fatalf("Addr() = %q", got)
}
}

func TestNegotiateIntegrationWithDomainConnect(t *testing.T) {
// Полный поток: negotiation + connect к example.com:443
domain := "example.com"
clientBuf := []byte{Version, 1, MethodNoAuth}
clientBuf = append(clientBuf, Version, CmdConnect, 0x00, AtypDomain, byte(len(domain)))
clientBuf = append(clientBuf, []byte(domain)...)
clientBuf = append(clientBuf, 0x01, 0xBB)

client := bytes.NewReader(clientBuf)
var server bytes.Buffer

if err := Negotiate(client, &server); err != nil {
t.Fatalf("Negotiate: %v", err)
}
req, err := ReadRequest(client)
if err != nil {
t.Fatalf("ReadRequest: %v", err)
}
if req.Host != domain || req.Port != 443 {
t.Fatalf("got %s:%d, want %s:443", req.Host, req.Port, domain)
}
if !strings.HasPrefix(req.Addr(), domain+":") {
t.Fatalf("Addr = %q", req.Addr())
}
}
