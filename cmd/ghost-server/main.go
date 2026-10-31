// ghost-server — REALITY-сервер с ghostmux поверх.
//
// Отличие от poc-server: после успешного REALITY handshake
// запускается ghostmux (EndpointHandler), а не ping/pong.
//
// Fallback и вся логика REALITY не изменяются: их обрабатывает
// reality.Server до возврата.
package main

import (
"context"
"crypto/ecdsa"
"crypto/elliptic"
"crypto/rand"
"crypto/x509"
"crypto/x509/pkix"
"encoding/hex"
"encoding/pem"
"log"
"math/big"
"net"
"os"
"time"

"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
"github.com/ghostquic/ghost-quic-v2/internal/proxy"
"github.com/xtls/reality"
)

const listenAddr = ":9444"

func main() {
destAddr := os.Getenv("REALITY_DEST")
if destAddr == "" {
destAddr = "www.microsoft.com:443"
}

privHex := os.Getenv("REALITY_PRIVATE")
if privHex == "" {
log.Fatal("REALITY_PRIVATE env required")
}
priv, err := hex.DecodeString(privHex)
if err != nil || len(priv) != 32 {
log.Fatalf("bad private key: %v len=%d", err, len(priv))
}

cert, err := genDummyCert()
if err != nil {
log.Fatalf("gen dummy cert: %v", err)
}

shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

cfg := &reality.Config{
Show:                   false,
Type:                   "tcp",
Dest:                   destAddr,
ServerNames:            map[string]bool{"microsoft.com": true},
PrivateKey:             priv,
ShortIds:               map[[8]byte]bool{shortID: true},
MaxTimeDiff:            60 * time.Second,
SessionTicketsDisabled: true,
Certificates:           []reality.Certificate{cert},
}

// Anti-fingerprint: обязательно для форка REALITY, иначе
// рукопожатие падает с "authentication failed".
// Инициализируется ДО первого Accept.
if ready := startAntiFingerprint(*cfg, 30*time.Second); ready {
log.Printf("anti-fingerprint: ready")
} else {
log.Printf("anti-fingerprint: TIMEOUT, proceeding without warm data")
}

ln, err := net.Listen("tcp", listenAddr)
if err != nil {
log.Fatalf("listen: %v", err)
}
log.Printf("ghost-server listening on %s, dest=%s", listenAddr, destAddr)

// Dialer для REALITY fallback (dest=microsoft.com) и для outbound proxy.
// Benchmark policy: loopback разрешён для origin 127.0.0.1:9990.
dial := proxy.NewTargetDialer(proxy.BenchmarkSSRFPolicy(), 10*time.Second)
cfg.DialContext = dial.DialContext
// // go startUDPListener(context.Background(), ":10443")

for {
rawConn, err := ln.Accept()
		if tc, ok := rawConn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetReadBuffer(4 * 1024 * 1024)
			tc.SetWriteBuffer(4 * 1024 * 1024)
		}
if err != nil {
log.Printf("accept: %v", err)
continue
}
go serve(rawConn, cfg, dial)
}
}

func serve(rawConn net.Conn, cfg *reality.Config, dial *proxy.TargetDialer) {
defer rawConn.Close()

// Pre-auth budget: 15s на handshake.
deadline := time.Now().Add(15 * time.Second)
rawConn.SetDeadline(deadline)

rc, err := reality.Server(context.Background(), rawConn, cfg)
if err != nil {
// Fallback отработан внутри reality.Server. Здесь — просто выход.
log.Printf("reality.Server %v: %v", rawConn.RemoteAddr(), err)
return
}
// Deadline очищаем после handshake.
rawConn.SetDeadline(time.Time{})

log.Printf("REALITY handshake OK from %v", rawConn.RemoteAddr())


	// Ghostmux поверх аутентифицированного REALITY byte-stream.
sess := ghostmux.NewSession()
if err := sess.BeginNegotiation(); err != nil {
log.Printf("session.BeginNegotiation: %v", err)
return
}
if err := sess.AcceptRemoteSettings(ghostmux.DefaultSettings()); err != nil {
log.Printf("session.AcceptRemoteSettings: %v", err)
return
}
sched := ghostmux.NewScheduler(0)
conn := ghostmux.NewConn(rc, sess, sched, 0)
handler := proxy.NewEndpointHandler(sess, conn, dial, proxy.DefaultServerConfig())

conn.Start(handler)
_ = conn.Wait()
log.Printf("ghost session closed: %v", rawConn.RemoteAddr())
}

func genDummyCert() (reality.Certificate, error) {
key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
return reality.Certificate{}, err
}
tmpl := &x509.Certificate{
SerialNumber: big.NewInt(1),
Subject:      pkix.Name{CommonName: "localhost"},
NotBefore:    time.Now().Add(-time.Hour),
NotAfter:     time.Now().Add(24 * time.Hour),
KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}
der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
if err != nil {
return reality.Certificate{}, err
}
certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
keyDER, err := x509.MarshalECPrivateKey(key)
if err != nil {
return reality.Certificate{}, err
}
keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
return reality.X509KeyPair(certPEM, keyPEM)
}
