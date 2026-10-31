package mobile

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	udpMaxFrameLen    = 64 * 1024
	udpDirClientToSrv = uint32(0)
	udpDirServerToCl  = uint32(1)
)

type udpCryptor struct {
	aead      cipher.AEAD
	sendDir   uint32
	recvDir   uint32
	sendCount uint64
	recvCount uint64
	mu        sync.Mutex
}

func newUDPCryptor(userKeyHex string, sendDir, recvDir uint32) (*udpCryptor, error) {
	key, err := hex.DecodeString(userKeyHex)
	if err != nil {
		return nil, err
	}
	r := hkdf.New(sha256.New, key, nil, []byte("ghost-quic-v1"))
	aeadKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, aeadKey); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return nil, err
	}
	return &udpCryptor{aead: aead, sendDir: sendDir, recvDir: recvDir}, nil
}

func (c *udpCryptor) seal(plaintext []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], c.sendDir)
	binary.BigEndian.PutUint64(n[4:12], c.sendCount)
	c.sendCount++
	return c.aead.Seal(nil, n, plaintext, nil)
}

func (c *udpCryptor) open(ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], c.recvDir)
	binary.BigEndian.PutUint64(n[4:12], c.recvCount)
	pt, err := c.aead.Open(nil, n, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.recvCount++
	return pt, nil
}

func readUDPFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 || length > udpMaxFrameLen {
		return nil, errors.New("bad len")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeUDPFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > udpMaxFrameLen {
		return errors.New("bad len")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

type quicFallbackTransport struct {
	serverAddr string
	userID     string
	keyHex     string
	mu         sync.Mutex
	quicConn   quic.Connection
	shared     *quicSharedStream
}

func newQUICFallbackTransport(serverAddr, userID, keyHex string) *quicFallbackTransport {
	return &quicFallbackTransport{
		serverAddr: serverAddr,
		userID:     userID,
		keyHex:     keyHex,
	}
}

func (t *quicFallbackTransport) OpenFlow(ctx context.Context, key flowKey, meta flowMeta) (udpFlow, error) {
	t.mu.Lock()
	if t.shared == nil {
		// Первое подключение, создаем соединение и стрим
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		}
		qConf := &quic.Config{
			MaxIdleTimeout:       30 * time.Second,
			HandshakeIdleTimeout: 5 * time.Second,
			KeepAlivePeriod:      15 * time.Second,
		}
		conn, err := quic.DialAddr(ctx, t.serverAddr, tlsConf, qConf)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		t.quicConn = conn

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}

		cr, err := newUDPCryptor(t.keyHex, udpDirClientToSrv, udpDirServerToCl)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}

		var raw []byte
		raw = append(raw, byte(len(t.userID)))
		raw = append(raw, []byte(t.userID)...)
		encTarget := cr.seal([]byte("UDP"))
		raw = append(raw, encTarget...)

		if err := writeUDPFrame(stream, raw); err != nil {
			t.mu.Unlock()
			return nil, err
		}

		t.shared = &quicSharedStream{
			stream: stream,
			cr:     cr,
			flows:  sync.Map{},
		}
		go t.shared.readLoop()
		log.Printf("[GO] QUIC Fallback connected to %s", t.serverAddr)
	}
	shared := t.shared
	t.mu.Unlock()

	destKey := key.Dest.String()
	if key.DestHost != "" {
		if strings.Contains(key.DestHost, ":") {
			destKey = key.DestHost
		} else {
			destKey = net.JoinHostPort(key.DestHost, strconv.Itoa(int(key.Dest.Port())))
		}
	}

	flowIface, _ := shared.flows.LoadOrStore(destKey, &quicFallbackFlow{
		parent:   shared,
		destHost: key.Dest.Addr().String(),
		destPort: int(key.Dest.Port()),
		ch:       make(chan datagram, 128),
	})
	return flowIface.(*quicFallbackFlow), nil
}

func (t *quicFallbackTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.quicConn != nil {
		err := t.quicConn.CloseWithError(0, "")
		t.quicConn = nil
		t.shared = nil
		return err
	}
	return nil
}

type quicSharedStream struct {
	stream  quic.Stream
	cr      *udpCryptor
	writeMu sync.Mutex
	flows   sync.Map
}

func (s *quicSharedStream) readLoop() {
	for {
		enc, err := readUDPFrame(s.stream)
		if err != nil {
			return // Соединение закрыто, выходим без спама в логи
		}
		pt, err := s.cr.open(enc)
		if err != nil {
			continue
		}
		peer, payload, err := parseUDPFrame(pt)
		if err != nil {
			continue
		}

		peerStr := peer.String()
		
		var targetFlow *quicFallbackFlow
		if v, ok := s.flows.Load(peerStr); ok {
			targetFlow = v.(*quicFallbackFlow)
		} else {
			// Фоллбэк: если точного совпадения нет, ищем по IP
			s.flows.Range(func(k, v interface{}) bool {
				if strings.HasPrefix(k.(string), peer.Addr().String()+":") {
					targetFlow = v.(*quicFallbackFlow)
					return false
				}
				return true
			})
		}

		if targetFlow != nil {
			select {
			case targetFlow.ch <- datagram{Payload: payload, Peer: peer}:
			default:
			}
		}
	}
}

type quicFallbackFlow struct {
	parent   *quicSharedStream
	destHost string
	destPort int
	ch       chan datagram
}

func (f *quicFallbackFlow) Write(ctx context.Context, payload []byte) error {
	frame := buildUDPFrame(f.destHost, f.destPort, payload)
	
	f.parent.writeMu.Lock()
	enc := f.parent.cr.seal(frame)
	err := writeUDPFrame(f.parent.stream, enc)
	f.parent.writeMu.Unlock()

	return err
}

func (f *quicFallbackFlow) Read(ctx context.Context) (datagram, error) {
	select {
	case dg, ok := <-f.ch:
		if !ok {
			return datagram{}, errors.New("flow closed")
		}
		return dg, nil
	case <-ctx.Done():
		return datagram{}, ctx.Err()
	}
}

func (f *quicFallbackFlow) Close() error {
	f.parent.flows.Delete(f.destHost + ":" + strconv.Itoa(f.destPort))
	return nil
}

func buildUDPFrame(host string, port int, data []byte) []byte {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, 0x01)
			out = append(out, ip4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03)
		out = append(out, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	out = append(out, portBuf[:]...)
	out = append(out, data...)
	return out
}

func parseUDPFrame(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, fmt.Errorf("empty")
	}
	atyp := b[0]
	idx := 1
	var ip net.IP
	switch atyp {
	case 0x01:
		if len(b) < idx+4+2 {
			return netip.AddrPort{}, nil, fmt.Errorf("short")
		}
		ip = net.IP(b[idx : idx+4])
		idx += 4
	case 0x04:
		if len(b) < idx+16+2 {
			return netip.AddrPort{}, nil, fmt.Errorf("short")
		}
		ip = net.IP(b[idx : idx+16])
		idx += 16
	default:
		return netip.AddrPort{}, nil, fmt.Errorf("bad atyp")
	}
	port := int(binary.BigEndian.Uint16(b[idx : idx+2]))
	idx += 2
	
	var addr netip.Addr
	if atyp == 0x01 {
		addr, _ = netip.AddrFromSlice(ip.To4())
	} else {
		addr, _ = netip.AddrFromSlice(ip.To16())
	}
	return netip.AddrPortFrom(addr, uint16(port)), b[idx:], nil
}