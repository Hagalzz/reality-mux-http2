package main

import (
"bufio"
"bytes"
"context"
"crypto/aes"
"crypto/cipher"
"crypto/ecdh"
"crypto/ed25519"
"crypto/hmac"
"crypto/sha256"
"crypto/sha512"
"crypto/tls"
"crypto/x509"
"encoding/binary"
"encoding/hex"
"encoding/json"
"errors"
"fmt"
"io"
"log"
"math/rand"
"net"
	"net/url"
"os"
"os/exec"
"os/signal"
"path/filepath"
"strings"
"sync"
"syscall"
"time"
"unsafe"

"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
"github.com/ghostquic/ghost-quic-v2/internal/proxy"
"github.com/quic-go/quic-go"
utls "github.com/refraction-networking/utls"
"golang.org/x/crypto/chacha20poly1305"
"golang.org/x/crypto/hkdf"
"golang.org/x/sys/windows/registry"
)

const (
chunkSize         = 32 * 1024
maxFrame          = 64 * 1024
httpProxyAddr     = "127.0.0.1:1080"
socksProxyAddr    = "127.0.0.1:1081"
dirClientToServer = uint32(0)
dirServerToClient = uint32(1)
)

type Config struct {
Protocol         string `json:"protocol"`
Server           string `json:"server"`
ServerName       string `json:"server_name"`
UserID           string `json:"user_id"`
UserKey          string `json:"user_key"`
RealityPublic    string `json:"reality_public"`
TLSHelloFragment bool   `json:"tls_hello_fragment"`
}

var cfg *Config

func loadConfig() (*Config, error) {
exe, err := os.Executable()
if err != nil { return nil, err }
dir := filepath.Dir(exe)

// 1. Сначала ищем config.json
cfgPath := filepath.Join(dir, "config.json")
if data, err := os.ReadFile(cfgPath); err == nil {
var c Config
if err := json.Unmarshal(data, &c); err == nil {
if c.Protocol == "" { c.Protocol = "quic" }
return &c, nil
}
}

// 2. Если нет, ищем link.txt (ghost://id:key:pub@ip:port)
linkPath := filepath.Join(dir, "link.txt")
data, err := os.ReadFile(linkPath)
if err != nil {
return nil, errors.New("не найден ни config.json, ни link.txt")
}

uri := strings.TrimSpace(string(data))
u, err := url.Parse(uri)
if err != nil || u.Scheme != "ghost" {
return nil, errors.New("неверный формат ссылки (должна начинаться с ghost://)")
}

user := u.User.Username()
pass, _ := u.User.Password()
host := u.Hostname()
port := u.Port()

if user == "" || pass == "" || host == "" || port == "" {
return nil, errors.New("ссылка должна быть в формате ghost://id:key:pub@ip:port")
}

parts := strings.Split(pass, ":")
if len(parts) != 2 {
return nil, errors.New("в ссылке должен быть user_key и reality_public через двоеточие")
}

c := Config{
Protocol:      "reality",
Server:        host + ":" + port,
ServerName:    "microsoft.com",
UserID:        user,
UserKey:       parts[0],
RealityPublic: parts[1],
}

// 3. Сохраняем как config.json для следующих запусков
if out, err := json.MarshalIndent(c, "", "  "); err == nil {
os.WriteFile(cfgPath, out, 0644)
}

return &c, nil
}

var (
user32     = syscall.NewLazyDLL("user32.dll")
wininet    = syscall.NewLazyDLL("wininet.dll")
procMsgBox = user32.NewProc("MessageBoxW")
procIntOpt = wininet.NewProc("InternetSetOptionW")
)

const (
MB_YESNO        = 0x00000004
MB_OK           = 0x00000000
MB_ICONQUESTION = 0x00000020
MB_ICONERROR    = 0x00000010
MB_ICONINFO     = 0x00000040
IDYES           = 6
)

func msgBox(title, text string, flags uint) int {
t, _ := syscall.UTF16PtrFromString(title)
x, _ := syscall.UTF16PtrFromString(text)
r, _, _ := procMsgBox.Call(0, uintptr(unsafe.Pointer(x)), uintptr(unsafe.Pointer(t)), uintptr(flags))
return int(r)
}

func setSystemProxy(enable bool) error {
k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
if err != nil { return err }
defer k.Close()
if enable {
k.SetDWordValue("ProxyEnable", 1)
k.SetStringValue("ProxyServer", httpProxyAddr)
k.SetStringValue("ProxyOverride", "<-loopback>")
} else {
k.SetDWordValue("ProxyEnable", 0)
}
procIntOpt.Call(0, 39, 0, 0)
procIntOpt.Call(0, 37, 0, 0)
return nil
}

func pidFilePath() string {
exe, _ := os.Executable()
return filepath.Join(filepath.Dir(exe), "ghost.pid")
}

func cleanup() {
setSystemProxy(false)
os.Remove(pidFilePath())
}

type quicWrapper struct { s *quic.Stream }
func (q *quicWrapper) Read(p []byte) (int, error)  { return q.s.Read(p) }
func (q *quicWrapper) Write(p []byte) (int, error) { return q.s.Write(p) }
func (q *quicWrapper) Close() error { q.s.CancelRead(0); q.s.CancelWrite(0); return nil }

var (
globalQUICMu   sync.Mutex
globalQUICSess *quic.Conn
)

func proxyThrough(localConn net.Conn, localReader io.Reader, target string) {
if cfg.Protocol == "reality" {
proxyThroughReality(localConn, localReader, target)
} else {
proxyThroughQUIC(localConn, localReader, target)
}
}

func proxyThroughReality(localConn net.Conn, localReader io.Reader, target string) {
host, portStr, err := net.SplitHostPort(target)
if err != nil { return }
var port uint16
for _, b := range []byte(portStr) {
if b < '0' || b > '9' { return }
port = port*10 + uint16(b-'0')
}

pub, err := hex.DecodeString(cfg.RealityPublic)
if err != nil || len(pub) != 32 { log.Printf("bad REALITY public key"); return }
shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

rc, err := dialReality(cfg.Server, pub, shortID[:])
if err != nil { log.Printf("reality dial: %v", err); return }
defer rc.Close()

sess := ghostmux.NewSession()
if err := sess.BeginNegotiation(); err != nil { return }
if err := sess.AcceptRemoteSettings(ghostmux.DefaultSettings()); err != nil { return }
sched := ghostmux.NewScheduler(0)
muxConn := ghostmux.NewConn(rc, sess, sched, 0)
client := proxy.NewClientHandler(muxConn, sess)
muxConn.Start(client)
defer muxConn.Close()

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
cs, err := client.Open(ctx, host, port)
cancel()
if err != nil { log.Printf("reality open: %v", err); return }
defer cs.Close()

var wg sync.WaitGroup
wg.Add(2)
go func() { defer wg.Done(); io.Copy(cs, localReader); cs.CloseWrite() }()
go func() { defer wg.Done(); io.Copy(localConn, cs); if tc, ok := localConn.(*net.TCPConn); ok { tc.CloseWrite() } }()
wg.Wait()
}

func getQUICSess(ctx context.Context) (*quic.Conn, error) {
globalQUICMu.Lock()
defer globalQUICMu.Unlock()
if globalQUICSess != nil {
_, err := globalQUICSess.OpenStreamSync(ctx)
if err == nil { return globalQUICSess, nil }
globalQUICSess.CloseWithError(0, "")
globalQUICSess = nil
}
tlsConf := &tls.Config{
ServerName: cfg.ServerName,
NextProtos: []string{"h3"},
MinVersion: tls.VersionTLS13,
}
quicConf := &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 15 * time.Second}
sess, err := quic.DialAddr(ctx, cfg.Server, tlsConf, quicConf)
if err != nil { return nil, err }
globalQUICSess = sess
return sess, nil
}

func proxyThroughQUIC(localConn net.Conn, localReader io.Reader, target string) {
ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
defer cancel()

sess, err := getQUICSess(ctx)
if err != nil { return }
stream, err := sess.OpenStreamSync(ctx)
if err != nil { return }
transport := &quicWrapper{stream}

cr, err := newCryptor(cfg.UserKey, dirClientToServer, dirServerToClient)
if err != nil { return }
encTarget := cr.seal([]byte(target))
authFrame := make([]byte, 0, 2+len(cfg.UserID)+len(encTarget))
authFrame = append(authFrame, 0xFF)
authFrame = append(authFrame, byte(len(cfg.UserID)))
authFrame = append(authFrame, []byte(cfg.UserID)...)
authFrame = append(authFrame, encTarget...)

if err := writeFrame(transport, authFrame); err != nil { return }

done := make(chan struct{}, 2)
go func() {
defer func() { done <- struct{}{} }()
buf := make([]byte, chunkSize)
for {
n, err := localReader.Read(buf)
if n > 0 {
padLen := rand.Intn(256)
payload := make([]byte, 2+n+padLen)
binary.BigEndian.PutUint16(payload[:2], uint16(n))
copy(payload[2:], buf[:n])
rand.Read(payload[2+n:])
enc := cr.seal(payload)
if werr := writeFrame(transport, enc); werr != nil { return }
}
if err != nil { return }
}
}()
go func() {
defer func() { done <- struct{}{} }()
for {
enc, err := readFrame(transport)
if err != nil { return }
pt, err := cr.open(enc)
if err != nil { return }
if len(pt) >= 2 {
realLen := int(binary.BigEndian.Uint16(pt[:2]))
if realLen > 0 && realLen <= len(pt)-2 { pt = pt[2 : 2+realLen] }
}
if _, err := localConn.Write(pt); err != nil { return }
}
}()
<-done
}

func handleHTTP(conn net.Conn) {
defer conn.Close()
br := bufio.NewReader(conn)
line, err := br.ReadString('\n')
if err != nil { return }
parts := strings.Fields(line)
if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") { return }
target := parts[1]
for { h, err := br.ReadString('\n'); if err != nil || h == "\r\n" || h == "\n" { break } }
conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
proxyThrough(conn, br, target)
}

func handleSOCKS5(conn net.Conn) {
defer conn.Close()
br := bufio.NewReader(conn)
header := make([]byte, 2)
if _, err := io.ReadFull(br, header); err != nil { return }
nMethods := int(header[1])
methods := make([]byte, nMethods)
io.ReadFull(br, methods)
conn.Write([]byte{0x05, 0x00})
req := make([]byte, 4)
if _, err := io.ReadFull(br, req); err != nil { return }
var host string
if req[3] == 0x01 { ip := make([]byte, 4); io.ReadFull(br, ip); host = net.IP(ip).String() } else if req[3] == 0x03 { l, _ := br.ReadByte(); domain := make([]byte, l); io.ReadFull(br, domain); host = string(domain) } else { return }
portBuf := make([]byte, 2)
io.ReadFull(br, portBuf)
port := binary.BigEndian.Uint16(portBuf)
target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
proxyThrough(conn, br, target)
}

func main() {
if len(os.Args) >= 2 && os.Args[1] == "--daemon" {
pid := os.Getpid()
os.WriteFile(pidFilePath(), []byte(fmt.Sprintf("%d", pid)), 0600)
exe, _ := os.Executable()
logPath := filepath.Join(filepath.Dir(exe), "ghost.log")
if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil { log.SetOutput(f) }

var err error
cfg, err = loadConfig()
if err != nil { log.Fatalf("config: %v", err) }

setSystemProxy(true)
httpLn, _ := net.Listen("tcp", httpProxyAddr)
socksLn, _ := net.Listen("tcp", socksProxyAddr)

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
go func() { <-sigCh; cleanup(); os.Exit(0) }()

go func() { for { c, err := httpLn.Accept(); if err == nil { go handleHTTP(c) } } }()
for { c, err := socksLn.Accept(); if err == nil { go handleSOCKS5(c) } }
}

pid, running := isDaemonRunning()
if running {
if msgBox("Ghost VPN", "VPN включен.\n\nВыключить?", MB_YESNO|MB_ICONQUESTION) == IDYES {
exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid)).Run()
time.Sleep(200 * time.Millisecond)
setSystemProxy(false)
os.Remove(pidFilePath())
}
return
}

if _, err := loadConfig(); err != nil { msgBox("Ghost VPN", "Ошибка: "+err.Error(), MB_OK|MB_ICONERROR); return }
if msgBox("Ghost VPN", "VPN выключен.\n\nВключить?", MB_YESNO|MB_ICONQUESTION) != IDYES { return }

exe, _ := os.Executable()
cmd := exec.Command(exe, "--daemon")
cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008}
cmd.Start()
time.Sleep(1 * time.Second)
msgBox("Ghost VPN", "VPN включен.", MB_OK|MB_ICONINFO)
}

func isDaemonRunning() (int, bool) {
data, err := os.ReadFile(pidFilePath())
if err != nil { return 0, false }
var pid int
fmt.Sscanf(string(data), "%d", &pid)
if pid == 0 { return 0, false }
out, _ := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
return pid, strings.Contains(string(out), fmt.Sprintf("%d", pid))
}

type cryptor struct {
aead      cipher.AEAD
sendDir   uint32
recvDir   uint32
sendCount uint64
recvCount uint64
}

func newCryptor(userKeyHex string, sendDir, recvDir uint32) (*cryptor, error) {
key, err := hex.DecodeString(userKeyHex)
if err != nil { return nil, err }
r := hkdf.New(sha256.New, key, nil, []byte("ghost-quic-v1"))
aeadKey := make([]byte, chacha20poly1305.KeySize)
if _, err := io.ReadFull(r, aeadKey); err != nil { return nil, err }
aead, err := chacha20poly1305.New(aeadKey)
if err != nil { return nil, err }
return &cryptor{aead: aead, sendDir: sendDir, recvDir: recvDir}, nil
}

func makeNonce(dir uint32, counter uint64) []byte {
n := make([]byte, 12)
binary.BigEndian.PutUint32(n[0:4], dir)
binary.BigEndian.PutUint64(n[4:12], counter)
return n
}

func (c *cryptor) seal(plaintext []byte) []byte {
nonce := makeNonce(c.sendDir, c.sendCount)
c.sendCount++
return c.aead.Seal(nil, nonce, plaintext, nil)
}

func (c *cryptor) open(ciphertext []byte) ([]byte, error) {
nonce := makeNonce(c.recvDir, c.recvCount)
pt, err := c.aead.Open(nil, nonce, ciphertext, nil)
if err != nil { return nil, err }
c.recvCount++
return pt, nil
}

func readFrame(r io.Reader) ([]byte, error) {
var hdr [4]byte
if _, err := io.ReadFull(r, hdr[:]); err != nil { return nil, err }
length := binary.BigEndian.Uint32(hdr[:])
if length == 0 || length > maxFrame { return nil, errors.New("invalid frame length") }
body := make([]byte, length)
if _, err := io.ReadFull(r, body); err != nil { return nil, err }
return body, nil
}

func writeFrame(w io.Writer, body []byte) error {
if len(body) == 0 || len(body) > maxFrame { return errors.New("invalid frame length") }
var hdr [4]byte
binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
if _, err := w.Write(hdr[:]); err != nil { return err }
_, err := w.Write(body)
return err
}

func dialReality(addr string, serverPub, shortID []byte) (net.Conn, error) {
tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
	}
if err != nil { return nil, err }

var authKey []byte
uCfg := &utls.Config{
ServerName:             "microsoft.com",
InsecureSkipVerify:     true,
NextProtos:             []string{"h2", "http/1.1"},
SessionTicketsDisabled: true,
CurvePreferences:       []utls.CurveID{utls.X25519},
VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
if len(rawCerts) == 0 { return errors.New("no certs") }
cert, err := x509.ParseCertificate(rawCerts[0])
if err != nil { return fmt.Errorf("parse cert: %w", err) }
pub, ok := cert.PublicKey.(ed25519.PublicKey)
if !ok { return errors.New("REALITY: not authenticated (fallback target)") }
h := hmac.New(sha512.New, authKey)
h.Write(pub)
expected := h.Sum(nil)
if !bytes.Equal(expected, cert.Signature) { return errors.New("REALITY: HMAC signature mismatch") }
return nil
},
}

uConn := utls.UClient(tcpConn, uCfg, utls.HelloChrome_120)
if err := uConn.BuildHandshakeState(); err != nil { tcpConn.Close(); return nil, fmt.Errorf("BuildHandshakeState: %w", err) }
hello := uConn.HandshakeState.Hello

hello.SessionId = make([]byte, 32)
copy(hello.Raw[39:], hello.SessionId)
hello.SessionId[0] = 26
hello.SessionId[1] = 3
hello.SessionId[2] = 27
hello.SessionId[3] = 0
binary.BigEndian.PutUint32(hello.SessionId[4:8], uint32(time.Now().Unix()))
copy(hello.SessionId[8:16], shortID)

pubKey, err := ecdh.X25519().NewPublicKey(serverPub)
if err != nil { tcpConn.Close(); return nil, fmt.Errorf("parse server pub: %w", err) }

ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
if ecdhe == nil { ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe }
if ecdhe == nil { tcpConn.Close(); return nil, errors.New("no ECDHE key share") }

ak, err := ecdhe.ECDH(pubKey)
if err != nil { tcpConn.Close(); return nil, fmt.Errorf("ECDH: %w", err) }

hk := hkdf.New(sha256.New, ak, hello.Random[:20], []byte("REALITY"))
authKey = make([]byte, len(ak))
if _, err := io.ReadFull(hk, authKey); err != nil { return nil, fmt.Errorf("hkdf: %w", err) }

block, err := aes.NewCipher(authKey)
if err != nil { tcpConn.Close(); return nil, fmt.Errorf("aes: %w", err) }
aead, err := cipher.NewGCM(block)
if err != nil { tcpConn.Close(); return nil, fmt.Errorf("gcm: %w", err) }

aad := make([]byte, len(hello.Raw))
copy(aad, hello.Raw)
aead.Seal(hello.SessionId[:0], hello.Random[20:32], hello.SessionId[:16], aad)
copy(hello.Raw[39:], hello.SessionId)

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := uConn.HandshakeContext(ctx); err != nil { tcpConn.Close(); return nil, fmt.Errorf("handshake: %w", err) }

return uConn, nil
}
