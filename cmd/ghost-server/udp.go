package main

import (
"context"
"crypto/cipher"
"crypto/sha256"
"crypto/tls"
"encoding/binary"
"encoding/hex"
"encoding/json"
"errors"
"fmt"
"io"
"log"
"math/rand"
"net"
"os"
"time"

"github.com/quic-go/quic-go"
"golang.org/x/crypto/chacha20poly1305"
"golang.org/x/crypto/hkdf"
)

const (
udpMaxFrameLen    = 64 * 1024
udpMaxUserIDLen   = 64
udpCertPath       = "/etc/ghost-quic/fullchain.pem"
udpKeyPath        = "/etc/ghost-quic/privkey.pem"
udpUsersPath      = "/etc/ghost-quic/users.json"
udpDirClientToSrv = uint32(0)
udpDirServerToCl  = uint32(1)
udpChunkSize      = 32 * 1024
udpDialTimeout    = 10 * time.Second
)

type udpUser struct {
KeyHex  string `json:"key_hex"`
Enabled bool   `json:"enabled"`
}

type udpUsersFile struct {
Users map[string]udpUser `json:"users"`
}

var udpUsersCache map[string]udpUser

func loadUDPUsers() error {
data, err := os.ReadFile(udpUsersPath)
if err != nil { return err }
var uf udpUsersFile
if err := json.Unmarshal(data, &uf); err != nil { return err }
udpUsersCache = uf.Users
return nil
}

func getUDPUser(id string) (udpUser, bool) {
u, ok := udpUsersCache[id]
return u, ok
}

type transportConn interface {
io.Reader
io.Writer
Close() error
}

type quicWrapper struct {
s quic.Stream
}

func (q *quicWrapper) Read(p []byte) (int, error)  { return q.s.Read(p) }
func (q *quicWrapper) Write(p []byte) (int, error) { return q.s.Write(p) }
func (q *quicWrapper) Close() error {
q.s.CancelRead(0)
q.s.CancelWrite(0)
return nil
}

type cryptor struct {
aead      cipher.AEAD
sendDir   uint32
recvDir   uint32
sendCount uint64
recvCount uint64
}

func newUDPCryptor(userKeyHex string, sendDir, recvDir uint32) (*cryptor, error) {
key, err := hex.DecodeString(userKeyHex)
if err != nil { return nil, err }
r := hkdf.New(sha256.New, key, nil, []byte("ghost-quic-v1"))
aeadKey := make([]byte, chacha20poly1305.KeySize)
if _, err := io.ReadFull(r, aeadKey); err != nil { return nil, err }
aead, err := chacha20poly1305.New(aeadKey)
if err != nil { return nil, err }
return &cryptor{aead: aead, sendDir: sendDir, recvDir: recvDir}, nil
}

func (c *cryptor) seal(plaintext []byte) []byte {
n := make([]byte, 12)
binary.BigEndian.PutUint32(n[0:4], c.sendDir)
binary.BigEndian.PutUint64(n[4:12], c.sendCount)
c.sendCount++
return c.aead.Seal(nil, n, plaintext, nil)
}

func (c *cryptor) open(ciphertext []byte) ([]byte, error) {
n := make([]byte, 12)
binary.BigEndian.PutUint32(n[0:4], c.recvDir)
binary.BigEndian.PutUint64(n[4:12], c.recvCount)
pt, err := c.aead.Open(nil, n, ciphertext, nil)
if err != nil { return nil, err }
c.recvCount++
return pt, nil
}

func readFrame(r io.Reader) ([]byte, error) {
var hdr [4]byte
if _, err := io.ReadFull(r, hdr[:]); err != nil { return nil, err }
length := binary.BigEndian.Uint32(hdr[:])
if length == 0 || length > udpMaxFrameLen { return nil, errors.New("bad len") }
body := make([]byte, length)
if _, err := io.ReadFull(r, body); err != nil { return nil, err }
return body, nil
}

func writeFrame(w io.Writer, body []byte) error {
if len(body) == 0 || len(body) > udpMaxFrameLen { return errors.New("bad len") }
var hdr [4]byte
binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
if _, err := w.Write(hdr[:]); err != nil { return err }
_, err := w.Write(body)
return err
}

// --- ХЕЛПЕРЫ ДЛЯ TCP ---
func udpIsForbiddenIP(ip net.IP) bool {
if ip == nil { return true }
if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() { return true }
if v4 := ip.To4(); v4 != nil {
if v4[0] == 169 && v4[1] == 254 { return true }
if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { return true }
if v4[0] == 0 { return true }
}
return false
}

func udpSafeDial(ctx context.Context, targetAddr string) (net.Conn, error) {
host, port, err := net.SplitHostPort(targetAddr)
if err != nil { return nil, fmt.Errorf("split host/port: %w", err) }
ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
if err != nil { return nil, err }
if len(ips) == 0 { return nil, fmt.Errorf("no addresses for %q", host) }
for _, ipa := range ips {
if udpIsForbiddenIP(ipa.IP) { return nil, fmt.Errorf("ssrf blocked: %s", ipa.IP) }
}
d := net.Dialer{Timeout: udpDialTimeout}
var lastErr error
for _, ipa := range ips {
conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ipa.IP.String(), port))
if err == nil { return conn, nil }
lastErr = err
}
return nil, lastErr
}

// --- ОБРАБОТКА ПОДКЛЮЧЕНИЙ ---
func startUDPListener(ctx context.Context, addr string) {
cert, err := tls.LoadX509KeyPair(udpCertPath, udpKeyPath)
if err != nil { log.Printf("[UDP] cert err: %v", err); return }
tlsConf := &tls.Config{
Certificates: []tls.Certificate{cert},
NextProtos:   []string{"h3"},
MinVersion:   tls.VersionTLS13,
}
quicConf := &quic.Config{
MaxIdleTimeout:       30 * time.Second,
HandshakeIdleTimeout: 5 * time.Second,
MaxIncomingStreams:   128,
KeepAlivePeriod:      15 * time.Second,
}

if err := loadUDPUsers(); err != nil { log.Printf("[UDP] users err: %v", err); return }
go func() {
for {
if err := loadUDPUsers(); err != nil { log.Printf("[UDP] reload: %v", err) }
time.Sleep(10 * time.Second)
}
}()

ln, err := quic.ListenAddr(addr, tlsConf, quicConf)
if err != nil { log.Printf("[UDP] listen %s: %v", addr, err); return }
log.Printf("[+] UDP/QUIC listening on %s", addr)
for {
conn, err := ln.Accept(ctx)
if err != nil { continue }
go handleQUICConn(ctx, conn)
}
}

func handleQUICConn(ctx context.Context, conn quic.Connection) {
defer conn.CloseWithError(0, "")
for {
stream, err := conn.AcceptStream(ctx)
if err != nil { return }
go handleConn(ctx, &quicWrapper{stream}, "quic")
}
}

func handleConn(ctx context.Context, conn transportConn, proto string) {
defer conn.Close()
raw, err := readFrame(conn)
if err != nil { return }
if len(raw) < 2 { return }
padded := false
var userID string
var encTarget []byte
if raw[0] == 0xFF {
padded = true
if len(raw) < 2 { return }
uidLen := int(raw[1])
if uidLen == 0 || uidLen > udpMaxUserIDLen || len(raw) < 2+uidLen+1 { return }
userID = string(raw[2 : 2+uidLen])
encTarget = raw[2+uidLen:]
} else {
uidLen := int(raw[0])
if uidLen == 0 || uidLen > udpMaxUserIDLen || len(raw) < 1+uidLen+1 { return }
userID = string(raw[1 : 1+uidLen])
encTarget = raw[1+uidLen:]
}

user, ok := getUDPUser(userID)
if !ok || !user.Enabled { return }

cr, err := newUDPCryptor(user.KeyHex, udpDirServerToCl, udpDirClientToSrv)
if err != nil { return }

plain, err := cr.open(encTarget)
if err != nil { return }
targetSite := string(plain)

if targetSite == "UDP" {
handleUDPStream(ctx, conn, cr, userID, proto)
return
}

// TCP over QUIC
remoteConn, err := udpSafeDial(ctx, targetSite)
if err != nil { return }
defer remoteConn.Close()

done := make(chan struct{}, 2)
go func() {
defer func() { done <- struct{}{} }()
for {
enc, err := readFrame(conn)
if err != nil { return }
pt, err := cr.open(enc)
if err != nil { return }
if padded {
if len(pt) < 2 { return }
realLen := int(binary.BigEndian.Uint16(pt[:2]))
if realLen == 0 || realLen > len(pt)-2 { return }
pt = pt[2 : 2+realLen]
}
if _, err := remoteConn.Write(pt); err != nil { return }
}
}()

go func() {
defer func() { done <- struct{}{} }()
buf := make([]byte, udpChunkSize)
for {
n, err := remoteConn.Read(buf)
if n > 0 {
var payload []byte
if padded {
padLen := rand.Intn(256)
payload = make([]byte, 2+n+padLen)
binary.BigEndian.PutUint16(payload[:2], uint16(n))
copy(payload[2:], buf[:n])
rand.Read(payload[2+n:])
} else {
payload = buf[:n]
}
enc := cr.seal(payload)
if werr := writeFrame(conn, enc); werr != nil { return }
}
if err != nil { return }
}
}()
<-done
}

func handleUDPStream(ctx context.Context, conn transportConn, cr *cryptor, userID, proto string) {
udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
if err != nil { return }
defer udpConn.Close()

done := make(chan struct{}, 2)

go func() {
defer func() { done <- struct{}{} }()
for {
enc, err := readFrame(conn)
if err != nil { return }
pt, err := cr.open(enc)
if err != nil { return }

if len(pt) >= 2 {
realLen := int(binary.BigEndian.Uint16(pt[:2]))
if realLen > 0 && realLen <= len(pt)-2 {
pt = pt[2 : 2+realLen]
}
}

host, port, data, err := parseUDPFrame(pt)
if err != nil { continue }
ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
if err != nil || len(ips) == 0 { continue }
target := &net.UDPAddr{IP: ips[0].IP, Port: port}
udpConn.WriteToUDP(data, target)
}
}()

go func() {
defer func() { done <- struct{}{} }()
buf := make([]byte, 65535)
for {
n, src, err := udpConn.ReadFromUDP(buf)
if err != nil { return }
if n <= 0 { continue }
frame := buildUDPFrame(src, buf[:n])

padLen := rand.Intn(256)
payload := make([]byte, 2+len(frame)+padLen)
binary.BigEndian.PutUint16(payload[:2], uint16(len(frame)))
copy(payload[2:], frame)
rand.Read(payload[2+len(frame):])
enc := cr.seal(payload)

if err := writeFrame(conn, enc); err != nil { return }
}
}()

<-done
}

func parseUDPFrame(b []byte) (string, int, []byte, error) {
if len(b) < 1 { return "", 0, nil, fmt.Errorf("empty") }
atyp := b[0]
idx := 1
var host string
switch atyp {
case 0x01:
if len(b) < idx+4+2 { return "", 0, nil, fmt.Errorf("short") }
host = net.IP(b[idx : idx+4]).String()
idx += 4
case 0x03:
if len(b) < idx+1 { return "", 0, nil, fmt.Errorf("short") }
dlen := int(b[idx])
idx++
if len(b) < idx+dlen+2 { return "", 0, nil, fmt.Errorf("short") }
host = string(b[idx : idx+dlen])
idx += dlen
case 0x04:
if len(b) < idx+16+2 { return "", 0, nil, fmt.Errorf("short") }
host = net.IP(b[idx : idx+16]).String()
idx += 16
default:
return "", 0, nil, fmt.Errorf("bad atyp")
}
port := int(binary.BigEndian.Uint16(b[idx : idx+2]))
idx += 2
return host, port, b[idx:], nil
}

func buildUDPFrame(src *net.UDPAddr, data []byte) []byte {
var out []byte
if ip4 := src.IP.To4(); ip4 != nil {
out = append(out, 0x01)
out = append(out, ip4...)
} else {
out = append(out, 0x04)
out = append(out, src.IP.To16()...)
}
var portBuf [2]byte
binary.BigEndian.PutUint16(portBuf[:], uint16(src.Port))
out = append(out, portBuf[:]...)
out = append(out, data...)
return out
}
