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
	"sync"
"time"

"github.com/xtls/reality"
)

const listenAddr = "0.0.0.0:9444"
const preauthBudget = 15 * time.Second

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
Show: false,
Type:        "tcp",
		Dest:        destAddr,
ServerNames: map[string]bool{"microsoft.com": true},
PrivateKey:  priv,
ShortIds:    map[[8]byte]bool{shortID: true},
MaxTimeDiff:           60 * time.Second,
		SessionTicketsDisabled: true,
DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
log.Printf("DIAL: %s %s ...", network, address)
c, err := safeDialContext(ctx, network, address)
if err != nil {
log.Printf("DIAL FAIL: %v", err)
} else {
log.Printf("DIAL OK: %s", c.RemoteAddr())
}
return c, err
},
Certificates: []reality.Certificate{cert},
}

ln, err := net.Listen("tcp", listenAddr)
if err != nil {
log.Fatalf("listen: %v", err)
}
log.Printf("REALITY poc-server (raw listener + reality.Server) listening on %s", listenAddr)

limiter := NewLimiter()

// Запускаем фоновый детектор длин post-handshake записей —
// без него Server() не сможет правильно применить padding для anti-fingerprint.
// Синхронно ждём готовности anti-fingerprint (или timeout 5s).
// Иначе первый handshake платит 5s внутреннего Sleep в форке.
ready := startAntiFingerprint(*cfg, 30*time.Second)
if ready {
log.Printf("anti-fingerprint: ready")
} else {
log.Printf("anti-fingerprint: TIMEOUT, proceeding without warm data")
}

for {
rawConn, err := ln.Accept()
if err != nil {
log.Printf("accept: %v", err)
continue
}
if !limiter.Allow(rawConn.RemoteAddr().String()) {
log.Printf("REJECT: limit exceeded for %v", rawConn.RemoteAddr())
rawConn.Close()
continue
}
		go func(c net.Conn) {
			defer limiter.Done(c.RemoteAddr().String())

			// Absolute pre-auth budget: 15s от accept до успешной
			// аутентификации. Deadline ставится один раз и не обновляется —
			// медленный target не может продлить бюджет.
			deadline := time.Now().Add(preauthBudget)

			// Shared box для target: DialContext заполняет, main снимает после успеха.
			var targetMu sync.Mutex
			var targetConn net.Conn

			connCfg := *cfg
			baseDial := connCfg.DialContext
			connCfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				tc, err := baseDial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				tc.SetDeadline(deadline)
				targetMu.Lock()
				targetConn = tc
				targetMu.Unlock()
				return tc, nil
			}

			c.SetDeadline(deadline)

			rc, err := reality.Server(context.Background(), c, &connCfg)
			if err == nil {
				c.SetDeadline(time.Time{})
				targetMu.Lock()
				if targetConn != nil {
					targetConn.SetDeadline(time.Time{})
				}
				targetMu.Unlock()
			}
			if err != nil {
				log.Printf("reality.Server %v: %v", c.RemoteAddr(), err)
				c.Close()
				return
			}
			handle(rc)
		}(rawConn)
}
}

func handle(conn net.Conn) {
log.Printf("REALITY handshake OK from %v", conn.RemoteAddr())
buf := make([]byte, 1024)
n, err := conn.Read(buf)
if err != nil {
log.Printf("read: %v", err)
return
}
log.Printf("server got %d bytes: %q", n, string(buf[:n]))

if _, err := conn.Write([]byte("pong\n")); err != nil {
log.Printf("write: %v", err)
return
}
log.Printf("server wrote pong, waiting before close")
time.Sleep(2 * time.Second)
conn.Close()
log.Printf("server closed")
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
