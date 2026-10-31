package main

import (
"bytes"
"context"
"crypto/aes"
"crypto/cipher"
"crypto/ecdh"
"crypto/ed25519"
"crypto/hmac"
"crypto/sha256"
"crypto/sha512"
"crypto/x509"
"encoding/binary"
"encoding/hex"
"errors"
"fmt"
"io"
"log"
"net"
"os"
"time"

utls "github.com/refraction-networking/utls"
"golang.org/x/crypto/hkdf"
)

const (
defaultAddr = "127.0.0.1:9444"
sni         = "microsoft.com"
versionX    = 26
versionY    = 3
versionZ    = 27
)

func main() {
pubHex := os.Getenv("REALITY_PUBLIC")
if pubHex == "" {
log.Fatal("REALITY_PUBLIC env required")
}
pub, err := hex.DecodeString(pubHex)
if err != nil || len(pub) != 32 {
log.Fatalf("bad public key: %v len=%d", err, len(pub))
}
addr := os.Getenv("REALITY_ADDR")
if addr == "" {
addr = defaultAddr
}
shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

conn, err := dialReality(addr, pub, shortID[:])
if err != nil {
log.Fatalf("dial: %v", err)
}
defer conn.Close()
log.Printf("=== handshake finished")

conn.SetDeadline(time.Now().Add(5 * time.Second))
if _, err := conn.Write([]byte("ping\n")); err != nil {
log.Fatalf("write: %v", err)
}
buf := make([]byte, 1024)
n, err := conn.Read(buf)
if err != nil {
log.Fatalf("read: %v", err)
}
log.Printf("server reply (%d bytes): %q", n, string(buf[:n]))
}

func dialReality(addr string, serverPub, shortID []byte) (net.Conn, error) {
tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
if err != nil {
return nil, err
}
log.Printf("[1] TCP connected")

var authKey []byte

uCfg := &utls.Config{
ServerName:             sni,
InsecureSkipVerify:     true,
NextProtos:             []string{"h2", "http/1.1"},
SessionTicketsDisabled: true,
CurvePreferences:       []utls.CurveID{utls.X25519},
VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
log.Printf("[verify] called with %d certs", len(rawCerts))
if len(rawCerts) == 0 {
return errors.New("no certs")
}
cert, err := x509.ParseCertificate(rawCerts[0])
if err != nil {
return fmt.Errorf("parse cert: %w", err)
}
pub, ok := cert.PublicKey.(ed25519.PublicKey)
if !ok {
		log.Printf("[verify] not ed25519, fallback target cert: %T", cert.PublicKey)
		pool := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, e := x509.ParseCertificate(raw); e == nil {
				pool.AddCert(c)
			}
		}
		if _, vErr := cert.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: pool}); vErr != nil {
			log.Printf("[verify] fallback target PKI failed: %v", vErr)
		} else {
			log.Printf("[verify] fallback target PKI OK - NOT a GHOST server")
		}
		return errors.New("REALITY: not authenticated (fallback target)")
}
h := hmac.New(sha512.New, authKey)
h.Write(pub)
expected := h.Sum(nil)
log.Printf("[verify] expected=%x  actual=%x", expected[:16], cert.Signature[:16])
if !bytes.Equal(expected, cert.Signature) {
return errors.New("REALITY: HMAC signature mismatch")
}
log.Printf("[verify] HMAC OK")
return nil
},
}

uConn := utls.UClient(tcpConn, uCfg, utls.HelloChrome_120)
if err := uConn.BuildHandshakeState(); err != nil {
tcpConn.Close()
return nil, fmt.Errorf("BuildHandshakeState: %w", err)
}
hello := uConn.HandshakeState.Hello
log.Printf("[2] BuildHandshakeState OK, Raw len=%d", len(hello.Raw))

hello.SessionId = make([]byte, 32)
copy(hello.Raw[39:], hello.SessionId)
hello.SessionId[0] = versionX
hello.SessionId[1] = versionY
hello.SessionId[2] = versionZ
hello.SessionId[3] = 0
binary.BigEndian.PutUint32(hello.SessionId[4:8], uint32(time.Now().Unix()))
copy(hello.SessionId[8:16], shortID)

pubKey, err := ecdh.X25519().NewPublicKey(serverPub)
if err != nil {
tcpConn.Close()
return nil, fmt.Errorf("parse server pub: %w", err)
}

ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
if ecdhe == nil {
ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
}
if ecdhe == nil {
tcpConn.Close()
return nil, errors.New("no ECDHE key share")
}
log.Printf("[4b] ecdhe type=%T", ecdhe)

ak, err := ecdhe.ECDH(pubKey)
if err != nil {
tcpConn.Close()
return nil, fmt.Errorf("ECDH: %w", err)
}

hk := hkdf.New(sha256.New, ak, hello.Random[:20], []byte("REALITY"))
authKey = make([]byte, len(ak))
if _, err := io.ReadFull(hk, authKey); err != nil {
return nil, fmt.Errorf("hkdf: %w", err)
}

block, err := aes.NewCipher(authKey)
if err != nil {
tcpConn.Close()
return nil, fmt.Errorf("aes: %w", err)
}
aead, err := cipher.NewGCM(block)
if err != nil {
tcpConn.Close()
return nil, fmt.Errorf("gcm: %w", err)
}

aad := make([]byte, len(hello.Raw))
copy(aad, hello.Raw)
aead.Seal(hello.SessionId[:0], hello.Random[20:32], hello.SessionId[:16], aad)
copy(hello.Raw[39:], hello.SessionId)

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
log.Printf("[11] calling HandshakeContext...")
if err := uConn.HandshakeContext(ctx); err != nil {
tcpConn.Close()
return nil, fmt.Errorf("handshake: %w", err)
}
log.Printf("[12] HandshakeContext returned OK")

return uConn, nil
}
