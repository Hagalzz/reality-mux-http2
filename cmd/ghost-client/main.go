// ghost-client — REALITY-клиент с ghostmux поверх.
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
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
	"github.com/ghostquic/ghost-quic-v2/internal/proxy"
	"github.com/ghostquic/ghost-quic-v2/internal/socks5"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

const (
	versionX   = 26
	versionY   = 3
	versionZ   = 27
	serverName = "microsoft.com"
)

func main() {
	var (
		targetAddr = flag.String("target", "127.0.0.1:9990", "origin to reach through GHOST")
		msg        = flag.String("msg", "ping", "message to send")
		timeout    = flag.Duration("timeout", 15*time.Second, "overall timeout")
		socksAddr  = flag.String("socks", "", "if set, run SOCKS5 listener (e.g. 127.0.0.1:1085)")
	)
	flag.Parse()

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
		addr = "127.0.0.1:9444"
	}

	shortID := [8]byte{0xa0, 0x01, 0x0f, 0x4f, 0, 0, 0, 0}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// dialReality скопирован из poc-client: без ctx (свой 10s timeout).
	// ctx используется ниже для Open.
	rc, err := dialReality(addr, pub, shortID[:])
	if err != nil {
		log.Fatalf("dialReality: %v", err)
	}
	defer rc.Close()
	log.Printf("REALITY handshake OK, remote=%v", rc.RemoteAddr())
	// Отправляем 16 нулей, чтобы сервер пропустил нас без записи в лимиты
	if _, err := rc.Write(make([]byte, 16)); err != nil {
		log.Fatalf("send devID: %v", err)
	}

	sess := ghostmux.NewSession()
	if err := sess.BeginNegotiation(); err != nil {
		log.Fatalf("session.BeginNegotiation: %v", err)
	}
	if err := sess.AcceptRemoteSettings(ghostmux.DefaultSettings()); err != nil {
		log.Fatalf("session.AcceptRemoteSettings: %v", err)
	}
	sched := ghostmux.NewScheduler(0)
	conn := ghostmux.NewConn(rc, sess, sched, 0)
	client := proxy.NewClientHandler(conn, sess)
	conn.Start(client)
	defer func() {
		conn.Close()
		_ = conn.Wait()
	}()

	if *socksAddr != "" {
		runSocksListener(*socksAddr, client)
		return
	}

	host, portStr, err := net.SplitHostPort(*targetAddr)
	if err != nil {
		log.Fatalf("bad target %q: %v", *targetAddr, err)
	}
	var port uint16
	for _, b := range []byte(portStr) {
		if b < '0' || b > '9' {
			log.Fatalf("bad port %q", portStr)
		}
		port = port*10 + uint16(b-'0')
	}

	openCtx, openCancel := context.WithTimeout(ctx, 5*time.Second)
	cs, err := client.Open(openCtx, host, port)
	openCancel()
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	log.Printf("stream opened: id=%d target=%s", cs.ID(), *targetAddr)

	if _, err := cs.Write([]byte(*msg)); err != nil {
		log.Fatalf("write: %v", err)
	}
	if err := cs.CloseWrite(); err != nil {
		log.Fatalf("closewrite: %v", err)
	}

	var resp bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := cs.Read(buf)
		if n > 0 {
			resp.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("read: %v", err)
		}
	}
	log.Printf("response: %q", resp.String())
}

func dialReality(addr string, serverPub, shortID []byte) (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if err != nil {
		return nil, err
	}
	log.Printf("[1] TCP connected")

	var authKey []byte

	uCfg := &utls.Config{
		ServerName:             serverName,
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
				if _, vErr := cert.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: pool}); vErr != nil {
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

func runSocksListener(addr string, ch *proxy.ClientHandler) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("socks5 listen %s: %v", addr, err)
	}
	log.Printf("socks5 listening on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("socks5 accept: %v", err)
			return
		}
		go handleSocksConn(c, ch)
	}
}

func handleSocksConn(c net.Conn, ch *proxy.ClientHandler) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5.Negotiate(c, c); err != nil {
		log.Printf("socks5 negotiate: %v", err)
		return
	}
	req, err := socks5.ReadRequest(c)
	if err != nil {
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, nil)
		return
	}

		if req.Cmd == socks5.CmdUDP {
		handleSocksUDP(c, ch, req)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cs, err := ch.Open(ctx, req.Host, req.Port)
	cancel()
	if err != nil {
		log.Printf("socks5 open %s: %v", req.Addr(), err)
		_ = socks5.WriteReply(c, socks5.RepHostUnreachable, nil)
		return
	}
	defer cs.Close()

	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	if err := socks5.WriteReply(c, socks5.RepSuccess, nil); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(cs, c)
		_ = cs.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, cs)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}