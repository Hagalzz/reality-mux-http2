package mobile

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
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
	"github.com/ghostquic/ghost-quic-v2/internal/proxy"
	"github.com/ghostquic/ghost-quic-v2/internal/socks5"
	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	versionX   = 26
	versionY   = 3
	versionZ   = 27
	serverName = "microsoft.com"

	// --- ЗАХАРДКОЖЕННЫЕ КЛЮЧИ ---
	hardcodedServerAddr = "89.22.232.244:9444"
	hardcodedPubKeyHex  = "e1edfb073368fd76d519c820843a88a37850729514a1d33096be70e76273c564"
	hardcodedUserIDHex  = "a0010f4f"
	hardcodedHy2Addr    = "89.22.232.244:20000"
	hardcodedHy2Pass    = "hCmVAC95Aec/MimFgJOJgQ=="
)

var (
	globalListener net.Listener
	globalConn     net.Conn
	globalMux      *ghostmux.Conn
	
	// Глобальная переменная для Hysteria 2 (ПК)
	globalHyTransport *hysteriaTransport

	tunMu      sync.Mutex
	tunCurrent *tunInstance

	protectReqFD   int32
	protectRespVal int32

	dnsCache sync.Map
)

type stream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type streamOpener interface {
	Open(ctx context.Context, host string, port uint16) (stream, error)
}

type udpStreamOpener interface {
	OpenUDP(ctx context.Context, host string, port uint16) (stream, error)
}

type clientHandlerAdapter struct {
	handler *proxy.ClientHandler
}

func (a *clientHandlerAdapter) Open(ctx context.Context, host string, port uint16) (stream, error) {
	cs, err := a.handler.Open(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (a *clientHandlerAdapter) OpenUDP(ctx context.Context, host string, port uint16) (stream, error) {
	cs, err := a.handler.OpenUDP(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func resolveDomain(ip string) string {
	if strings.HasPrefix(ip, "91.108.") || strings.HasPrefix(ip, "149.154.") {
		return "149.154.167.51"
	}
	if val, ok := dnsCache.Load(ip); ok {
		return val.(string)
	}
	return ip
}

// --- БЕЗОПАСНОСТЬ И TUN ---

func GetProtectRequest() int64 {
	if atomic.LoadInt32(&protectReqFD) != 0 {
		fd := atomic.LoadInt32(&protectReqFD)
		atomic.StoreInt32(&protectReqFD, 0)
		return int64(fd)
	}
	return 0
}

func SubmitProtectResult(ok bool) {
	if ok {
		atomic.StoreInt32(&protectRespVal, 1)
	} else {
		atomic.StoreInt32(&protectRespVal, -1)
	}
}

func requestProtect(fd int) bool {
	atomic.StoreInt32(&protectRespVal, 0)
	atomic.StoreInt32(&protectReqFD, int32(fd))
	for i := 0; i < 100; i++ {
		resp := atomic.LoadInt32(&protectRespVal)
		if resp == 1 {
			return true
		}
		if resp == -1 {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func protectedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				if !requestProtect(int(fd)) {
					protectErr = errors.New("protect failed")
				}
			})
			if err != nil {
				return err
			}
			return protectErr
		},
	}
}

type safeClient struct {
	mu     sync.Mutex
	client streamOpener
	conn   *ghostmux.Conn
	rc     net.Conn
	closed bool
	dialFn func() (streamOpener, *ghostmux.Conn, net.Conn, error)
}

func (s *safeClient) Open(ctx context.Context, host string, port uint16) (stream, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, errors.New("client closed")
		}
		c := s.client
		conn := s.conn
		s.mu.Unlock()

		if c == nil {
			newClient, newConn, newRc, err := s.reconnect(ctx)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			s.client = newClient
			s.conn = newConn
			s.rc = newRc
			s.mu.Unlock()
			continue
		}

		strm, err := c.Open(ctx, host, port)
		if err == nil {
			return strm, nil
		}

		isDead := false
		if conn != nil && conn.Err() != nil {
			isDead = true
		} else if strings.Contains(err.Error(), "scheduler closed") ||
			strings.Contains(err.Error(), "connection abort") ||
			strings.Contains(err.Error(), "EOF") ||
			strings.Contains(err.Error(), "ghostmux connection closed") {
			isDead = true
		}

		if isDead {
			s.mu.Lock()
			if s.client == c {
				if s.rc != nil { s.rc.Close() }
				if s.conn != nil { s.conn.Close() }
				s.client = nil
				s.conn = nil
				s.rc = nil
			}
			s.mu.Unlock()
			continue
		}
		return nil, err
	}
}

func (s *safeClient) OpenUDP(ctx context.Context, host string, port uint16) (stream, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, errors.New("client closed")
		}
		c := s.client
		conn := s.conn
		s.mu.Unlock()

		if c == nil {
			newClient, newConn, newRc, err := s.reconnect(ctx)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			s.client = newClient
			s.conn = newConn
			s.rc = newRc
			s.mu.Unlock()
			continue
		}

		u, ok := c.(udpStreamOpener)
		if !ok {
			return nil, errors.New("client does not support UDP")
		}

		strm, err := u.OpenUDP(ctx, host, port)
		if err == nil {
			return strm, nil
		}

		isDead := false
		if conn != nil && conn.Err() != nil {
			isDead = true
		} else if strings.Contains(err.Error(), "scheduler closed") ||
			strings.Contains(err.Error(), "connection abort") ||
			strings.Contains(err.Error(), "EOF") ||
			strings.Contains(err.Error(), "ghostmux connection closed") {
			isDead = true
		}

		if isDead {
			s.mu.Lock()
			if s.client == c {
				if s.rc != nil { s.rc.Close() }
				if s.conn != nil { s.conn.Close() }
				s.client = nil
				s.conn = nil
				s.rc = nil
			}
			s.mu.Unlock()
			continue
		}
		return nil, err
	}
}

func (s *safeClient) reconnect(ctx context.Context) (streamOpener, *ghostmux.Conn, net.Conn, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		default:
		}
		client, conn, rc, err := s.dialFn()
		if err == nil {
			log.Printf("[GO] Reconnect successful!")
			return client, conn, rc, nil
		}
		log.Printf("[GO] Reconnect failed: %v, retrying in 1s...", err)
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

func (s *safeClient) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.rc != nil { s.rc.Close() }
	if s.conn != nil { s.conn.Close() }
}

type tunInstance struct {
	file       *os.File
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	safeClient *safeClient
	stack      *stack.Stack
	ep         *channel.Endpoint
	state      string
	mu         sync.Mutex
}

func (t *tunInstance) setState(state string) {
	t.mu.Lock()
	t.state = state
	t.mu.Unlock()
}

func (t *tunInstance) getState() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func GetTunStateV2() string {
	tunMu.Lock()
	inst := tunCurrent
	tunMu.Unlock()

	if inst == nil {
		return "STOPPED"
	}
	return inst.getState()
}

func StartTunV2(fd int64, mtu int64, mode string, deviceID string) string {
	if fd < 0 || uint64(fd) > uint64(^uint(0)>>1) {
		return "error: invalid fd range"
	}

	file := os.NewFile(uintptr(fd), "ghost-tun")
	if file == nil {
		return "error: invalid tun fd"
	}

	if mtu < 576 || mtu > 65535 {
		_ = file.Close()
		return "error: invalid mtu"
	}

	pub, err := hex.DecodeString(hardcodedPubKeyHex)
	if err != nil || len(pub) != 32 {
		_ = file.Close()
		return fmt.Sprintf("error pubkey: %v", err)
	}

	userIDBytes, err := hex.DecodeString(hardcodedUserIDHex)
	if err != nil {
		_ = file.Close()
		return fmt.Sprintf("error userID: %v", err)
	}
	var shortID [8]byte
	copy(shortID[:], userIDBytes)

	hash := sha256.Sum256([]byte(deviceID))
	var devID [16]byte
	copy(devID[:], hash[:16])

	ctx, cancel := context.WithCancel(context.Background())
	inst := &tunInstance{
		file:   file,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
		state:  "STARTING",
	}

	tunMu.Lock()
	if tunCurrent != nil {
		tunMu.Unlock()
		cancel()
		_ = file.Close()
		return "error: tun already running or stopping"
	}
	tunCurrent = inst
	tunMu.Unlock()

	go runTun(inst, hardcodedServerAddr, pub, shortID, hardcodedHy2Addr, hardcodedHy2Pass, int(mtu), mode, devID)
	return "started"
}

func StopTun() {
	tunMu.Lock()
	inst := tunCurrent
	if inst != nil {
		inst.setState("STOPPING")
	}
	tunMu.Unlock()

	if inst != nil {
		inst.cancel()
	}
}

func runTun(t *tunInstance, serverAddr string, pub []byte, shortID [8]byte, hy2Addr string, hy2Pass string, mtu int, mode string, devID [16]byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[GO] PANIC in runTun: %v\n%s", r, debug.Stack())
			t.setState("ERROR")
		}
		t.cancel()

		if t.stack != nil {
			t.stack.Close()
			t.stack = nil
		}
		if t.safeClient != nil {
			t.safeClient.Close()
			t.safeClient = nil
		}
		_ = t.file.Close()

		t.mu.Lock()
		if t.state != "ERROR" {
			t.state = "STOPPED"
		}
		t.mu.Unlock()

		close(t.done)

		tunMu.Lock()
		if tunCurrent == t {
			tunCurrent = nil
		}
		tunMu.Unlock()
		log.Printf("[GO] TUN instance stopped (final state: %s)", t.getState())
	}()

	dialFn := func() (streamOpener, *ghostmux.Conn, net.Conn, error) {
		rc, err := dialRealityContext(t.ctx, serverAddr, pub, shortID[:])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dial reality: %w", err)
		}

		// === ОТПРАВЛЯЕМ DEVICE ID В САМЫЙ НАЧАЛО ПОСЛЕ ХЕНДШЕЙКА ===
		if _, err := rc.Write(devID[:]); err != nil {
			rc.Close()
			return nil, nil, nil, fmt.Errorf("send deviceID: %w", err)
		}

		sess := ghostmux.NewSession()
		if err := sess.BeginNegotiation(); err != nil {
			rc.Close()
			return nil, nil, nil, fmt.Errorf("negotiate: %w", err)
		}
		if err := sess.AcceptRemoteSettings(ghostmux.DefaultSettings()); err != nil {
			rc.Close()
			return nil, nil, nil, fmt.Errorf("settings: %w", err)
		}

		sched := ghostmux.NewScheduler(0)
		conn := ghostmux.NewConn(rc, sess, sched, 0)
		client := proxy.NewClientHandler(conn, sess)
		conn.Start(client)

		return &clientHandlerAdapter{handler: client}, conn, rc, nil
	}

	safeClient := &safeClient{dialFn: dialFn}
	t.safeClient = safeClient

	var tcpClient streamOpener
	var udpTrans udpTransport

	if mode == "hysteria" {
		// ИЗМЕНЕНО: Превращаем devID в hex-строку для Hysteria 2
		hy2DeviceID := hex.EncodeToString(devID[:])
		hy2Transport, err := newHysteriaTransport(hy2Addr, hy2Pass, hy2DeviceID)
		if err != nil {
			log.Printf("[GO] Hysteria 2 init failed: %v", err)
			t.setState("ERROR")
			return
		}
		log.Printf("[GO] Hysteria 2 initialized successfully. Mode: HYSTERIA 2")
		
					// ИСПОЛЬЗУЕМ НАТИВНУЮ HYSTERIA 2 ДЛЯ ВСЕГО ТРАФИКА
			tcpClient = hy2Transport
			
			// УМНЫЙ РОУТЕР: Telegram -> QUIC Fallback (порт 9444), Остальное -> Hysteria 2
			serverIP := strings.Split(hy2Addr, ":")[0]
			quicFallbackAddr := serverIP + ":9444"
			quicTrans := newQUICFallbackTransport(quicFallbackAddr, "telegram", "0123456789abcdef0123456789abcdef")
			udpTrans = newSmartTransport(hy2Transport, quicTrans) 
		
	} else {
		log.Printf("[GO] Initializing REALITY...")
		c, conn, rc, err := safeClient.reconnect(t.ctx)
		if err != nil {
			log.Printf("[GO] Initial connection failed: %v", err)
			t.setState("ERROR")
			return
		}
		safeClient.client = c
		safeClient.conn = conn
		safeClient.rc = rc
		log.Printf("[GO] REALITY handshake OK. Mode: REALITY")
		tcpClient = safeClient
		udpTrans = &fakeUDPTransport{}
	}

	if t.ctx.Err() != nil {
		return
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	{
		tcpSackEnabled := tcpip.TCPSACKEnabled(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSackEnabled)
	}

	{
		rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 212992, Max: 4194304}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)
		sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 212992, Max: 4194304}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)
		modRcv := tcpip.TCPModerateReceiveBufferOption(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &modRcv)
	}

	t.stack = s

	ep := channel.New(2048, uint32(mtu), "")
	t.ep = ep

	if err := s.CreateNIC(1, ep); err != nil {
		log.Printf("[GO] CreateNIC error: %v", err)
		t.setState("ERROR")
		return
	}

	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	udpManager := newUDPManager(udpTrans)

	tcpFwd := tcp.NewForwarder(s, 65535, 256, func(r *tcp.ForwarderRequest) {
		go handleTCPForward(r, tcpClient, t.ctx)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort == 53 {
			go handleUDPDNS(r, tcpClient, t.ctx)
			return true
		}

		if mode == "reality" {
			return false
		}

		go handleUDPFlow(r, udpManager, t.ctx)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[GO] PANIC in TUN->gVisor: %v\n%s", r, debug.Stack())
			}
		}()
		buf := make([]byte, mtu)
		for {
			n, err := t.file.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
				})
				proto := header.IPv4ProtocolNumber
				if buf[0]>>4 == 6 {
					proto = header.IPv6ProtocolNumber
				}
				ep.InjectInbound(proto, pkt)
				pkt.DecRef()
			}
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[GO] PANIC in gVisor->TUN: %v\n%s", r, debug.Stack())
			}
		}()
		for {
			pkt := ep.ReadContext(t.ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			_, _ = t.file.Write(view.AsSlice())
			pkt.DecRef()
		}
	}()

	if t.ctx.Err() == nil {
		t.setState("CONNECTED")
		log.Printf("[GO] TUN stack UP (gVisor + mode: %s)", mode)
	}

	<-t.ctx.Done()
	log.Printf("[GO] TUN got stop signal")
}

func handleTCPForward(r *tcp.ForwarderRequest, ch streamOpener, parentCtx context.Context) {
	completed := false
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[GO] PANIC in handleTCPForward: %v\n%s", rec, debug.Stack())
		}
		if !completed {
			r.Complete(true)
		}
	}()

	id := r.ID()
	var wq waiter.Queue
	gvisorEp, gvErr := r.CreateEndpoint(&wq)
	if gvErr != nil {
		return
	}
	defer gvisorEp.Close()

	r.Complete(false)
	completed = true

	localConn := gonet.NewTCPConn(&wq, gvisorEp)
	defer localConn.Close()

	ip := id.LocalAddress.String()
	port := uint16(id.LocalPort)

	host := resolveDomain(ip)

	log.Printf("[GO] TUN intercepted TCP -> %s:%d (resolved: %s)", ip, port, host)

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	cs, err := ch.Open(ctx, host, port)
	cancel()

	if err != nil {
		log.Printf("[GO] TUN ch.Open failed for %s:%d: %v", host, port, err)
		return
	}
	defer cs.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(cs, localConn, buf)
		_ = cs.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(localConn, cs, buf)
		_ = localConn.CloseWrite()
	}()
	wg.Wait()
}

func handleUDPFlow(r *udp.ForwarderRequest, mgr *udpManager, parentCtx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[GO] PANIC in handleUDPFlow: %v\n%s", rec, debug.Stack())
		}
	}()

	id := r.ID()
	var wq waiter.Queue
	gvisorEp, gvErr := r.CreateEndpoint(&wq)
	if gvErr != nil {
		return
	}
	defer gvisorEp.Close()

	conn := gonet.NewUDPConn(&wq, gvisorEp)
	defer conn.Close()

	srcAddr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstAddr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	ip := dstAddr.String()

	key := flowKey{
		IngressID: 1,
		Protocol:  17,
		Source:    netip.AddrPortFrom(srcAddr, id.RemotePort),
		Dest:      netip.AddrPortFrom(dstAddr, id.LocalPort),
	}

	if val, ok := dnsCache.Load(ip); ok {
		log.Printf("[GO] UDP flow mapping (DNS): %s -> %s", ip, val.(string))
	}

	flow, err := mgr.transport.OpenFlow(parentCtx, key, flowMeta{})
	if err != nil {
		log.Printf("[GO] Failed to open UDP flow to %s: %v", ip, err)
		return
	}
	defer flow.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = flow.Write(parentCtx, buf[:n])
		}
	}()

	for {
			dg, err := flow.Read(parentCtx)
			if err != nil {
				return
			}
			
			// Используем Write, так как сокет уже соединен с key.Dest (Совет от Sol)
			_, err = conn.Write(dg.Payload)
			if err != nil {
				log.Printf("[GO] TUN write error: %v", err)
			}
		} // <--- Эта скобка закрывает цикл for
	} // <--- ВОТ ЭТУ СКОБКУ ТЫ ПОТЕРЯЛ (она закрывает func handleUDPFlow)

func handleUDPDNS(r *udp.ForwarderRequest, ch streamOpener, parentCtx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[GO] PANIC in handleUDPDNS: %v\n%s", rec, debug.Stack())
		}
	}()

	var wq waiter.Queue
	gvisorEp, gvErr := r.CreateEndpoint(&wq)
	if gvErr != nil {
		return
	}
	defer gvisorEp.Close()

	conn := gonet.NewUDPConn(&wq, gvisorEp)
	defer conn.Close()

	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil || n == 0 {
		return
	}

	var req dns.Msg
	if err := req.Unpack(buf[:n]); err == nil {
		if len(req.Question) > 0 {
			domain := req.Question[0].Name

			ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
			defer cancel()

			cs, err := ch.Open(ctx, "1.1.1.1", 53)
			if err != nil {
				return
			}
			defer cs.Close()

			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := cs.Write(lenBuf); err != nil {
				return
			}
			if _, err := cs.Write(buf[:n]); err != nil {
				return
			}

			if _, err := io.ReadFull(cs, lenBuf); err != nil {
				return
			}
			respLen := binary.BigEndian.Uint16(lenBuf)
			if respLen == 0 || respLen > 4096 {
				return
			}
			respBuf := make([]byte, respLen)
			if _, err := io.ReadFull(cs, respBuf); err != nil {
				return
			}

			var resp dns.Msg
			if err := resp.Unpack(respBuf); err == nil {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						dnsCache.Store(a.A.String(), strings.TrimSuffix(domain, "."))
						log.Printf("[GO] DNS Cache: %s -> %s", a.A.String(), strings.TrimSuffix(domain, "."))
					}
					if aaaa, ok := ans.(*dns.AAAA); ok {
						dnsCache.Store(aaaa.AAAA.String(), strings.TrimSuffix(domain, "."))
						log.Printf("[GO] DNS Cache: %s -> %s", aaaa.AAAA.String(), strings.TrimSuffix(domain, "."))
					}
				}
			}

			_, _ = conn.WriteTo(respBuf, addr)
			return
		}
	}

	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	cs, err := ch.Open(ctx, "1.1.1.1", 53)
	if err != nil {
		return
	}
	defer cs.Close()

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(n))
	if _, err := cs.Write(lenBuf); err != nil {
		return
	}
	if _, err := cs.Write(buf[:n]); err != nil {
		return
	}

	if _, err := io.ReadFull(cs, lenBuf); err != nil {
		return
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen == 0 || respLen > 4096 {
		return
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(cs, respBuf); err != nil {
		return
	}

	_, _ = conn.WriteTo(respBuf, addr)
}

func dialRealityContext(parentCtx context.Context, addr string, serverPub, shortID []byte) (net.Conn, error) {
	dialer := protectedDialer(5 * time.Second)
	tcpConn, err := dialer.DialContext(parentCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	var authKey []byte
	uCfg := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
		CurvePreferences:       []utls.CurveID{utls.X25519},
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certs")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse cert: %w", err)
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("REALITY: not authenticated")
			}
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if !bytes.Equal(h.Sum(nil), cert.Signature) {
				return errors.New("REALITY: HMAC signature mismatch")
			}
			return nil
		},
	}

	uConn := utls.UClient(tcpConn, uCfg, utls.HelloChrome_120)
	if err := uConn.BuildHandshakeState(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	hello := uConn.HandshakeState.Hello
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

	ak, err := ecdhe.ECDH(pubKey)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	hk := hkdf.New(sha256.New, ak, hello.Random[:20], []byte("REALITY"))
	authKey = make([]byte, len(ak))
	if _, err := io.ReadFull(hk, authKey); err != nil {
		tcpConn.Close()
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

	hsCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	if err := uConn.HandshakeContext(hsCtx); err != nil {
		cancel()
		tcpConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	cancel()

	if err := uConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}

	return uConn, nil
}

// --- ФУНКЦИИ ДЛЯ WINDOWS (БЕЗ ANDROID PROTECT) ---

func dialRealityPC(addr string, serverPub, shortID []byte) (net.Conn, error) {
	return dialRealityContextPC(context.Background(), addr, serverPub, shortID)
}

func dialRealityContextPC(parentCtx context.Context, addr string, serverPub, shortID []byte) (net.Conn, error) {
	// Используем обычный сетевой диалайзер для Windows, без Android-защиты
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tcpConn, err := dialer.DialContext(parentCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	// Дальше копируем логику REALITY handshake
	var authKey []byte
	uCfg := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
		CurvePreferences:       []utls.CurveID{utls.X25519},
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certs")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse cert: %w", err)
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("REALITY: not authenticated")
			}
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if !bytes.Equal(h.Sum(nil), cert.Signature) {
				return errors.New("REALITY: HMAC signature mismatch")
			}
			return nil
		},
	}

	uConn := utls.UClient(tcpConn, uCfg, utls.HelloChrome_120)
	if err := uConn.BuildHandshakeState(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	hello := uConn.HandshakeState.Hello
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

	ak, err := ecdhe.ECDH(pubKey)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	hk := hkdf.New(sha256.New, ak, hello.Random[:20], []byte("REALITY"))
	authKey = make([]byte, len(ak))
	if _, err := io.ReadFull(hk, authKey); err != nil {
		tcpConn.Close()
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

	hsCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	if err := uConn.HandshakeContext(hsCtx); err != nil {
		cancel()
		tcpConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	cancel()

	if err := uConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}

	return uConn, nil
}

func StartClient(serverAddr string, pubKeyHex string, socksAddr string) string {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != 32 {
		return fmt.Sprintf("error pubkey: %v", err)
	}

	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return fmt.Sprintf("error listen: %v", err)
	}
	globalListener = ln
	log.Printf("[GO] SOCKS5 listening on %s", socksAddr)

	shortID := [8]byte{0xa0, 0x01, 0x0f, 0x4f, 0, 0, 0, 0}
	rc, err := dialRealityPC(serverAddr, pub, shortID[:])
	if err != nil {
		ln.Close()
		return fmt.Sprintf("error dial: %v", err)
	}
	
	// Отправляем пустой devID (16 нулей), так как ПК-клиент пока не использует лимиты
	if _, err := rc.Write(make([]byte, 16)); err != nil {
		ln.Close()
		rc.Close()
		return fmt.Sprintf("error send devID: %v", err)
	}

	globalConn = rc
	log.Printf("[GO] REALITY handshake OK")

	sess := ghostmux.NewSession()
	if err := sess.BeginNegotiation(); err != nil {
		ln.Close()
		rc.Close()
		return fmt.Sprintf("error negotiate: %v", err)
	}
	if err := sess.AcceptRemoteSettings(ghostmux.DefaultSettings()); err != nil {
		ln.Close()
		rc.Close()
		return fmt.Sprintf("error settings: %v", err)
	}

	sched := ghostmux.NewScheduler(0)
	conn := ghostmux.NewConn(rc, sess, sched, 0)
	globalMux = conn
	client := proxy.NewClientHandler(conn, sess)
	conn.Start(client)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSocksConn(c, client)
		}
	}()

	return "Client started successfully"
}

// НОВАЯ ФУНКЦИЯ: Запуск Hysteria 2 для ПК
func StartHysteriaClient(serverAddr, auth, socksAddr string) string {
	// Отправляем 16 нулей, чтобы сервер не считал ПК за телефон
	hyTransport, err := newHysteriaTransport(serverAddr, auth, "00000000000000000000000000000000")
	if err != nil {
		return "error: " + err.Error()
	}
	globalHyTransport = hyTransport

	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return "error listen: " + err.Error()
	}
	globalListener = ln
	log.Printf("[GO] SOCKS5 (Hysteria 2) listening on %s", socksAddr)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSocksConnHy2(c, hyTransport)
		}
	}()
	return "Client started successfully"
}

func StopClient() {
	log.Printf("[GO] StopClient called")
	if globalListener != nil {
		globalListener.Close()
		globalListener = nil
	}
	if globalMux != nil {
		globalMux.Close()
		globalMux = nil
	}
	if globalConn != nil {
		globalConn.Close()
		globalConn = nil
	}
	// Закрываем Hysteria 2, если он был запущен
	if globalHyTransport != nil {
		globalHyTransport.Close()
		globalHyTransport = nil
	}
}

func dialReality(addr string, serverPub, shortID []byte) (net.Conn, error) {
	return dialRealityContext(context.Background(), addr, serverPub, shortID)
}

func handleSocksConn(c net.Conn, ch *proxy.ClientHandler) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5.Negotiate(c, c); err != nil {
		return
	}
	req, err := socks5.ReadRequest(c)
	if err != nil {
		log.Printf("[GO] SOCKS5 ReadRequest failed (0x01): %v", err)
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, nil)
		return
	}

	if req.Cmd == socks5.CmdUDP {
		_ = socks5.WriteReply(c, socks5.RepSuccess, nil)
		_, _ = io.Copy(io.Discard, c)
		return
	}

	log.Printf("[GO] TCP request: %s", req.Addr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cs, err := ch.Open(ctx, req.Host, req.Port)
	cancel()
	if err != nil {
		log.Printf("[GO] ch.Open failed for %s: %v", req.Addr(), err)
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
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(cs, c, buf)
		_ = cs.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(c, cs, buf)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// НОВЫЙ ОБРАБОТЧИК: для Hysteria 2
func handleSocksConnHy2(c net.Conn, ch *hysteriaTransport) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5.Negotiate(c, c); err != nil {
		return
	}
	req, err := socks5.ReadRequest(c)
	if err != nil {
		log.Printf("[GO] SOCKS5 ReadRequest failed (HY2): %v", err)
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, nil)
		return
	}

	if req.Cmd == socks5.CmdUDP {
		_ = socks5.WriteReply(c, socks5.RepSuccess, nil)
		_, _ = io.Copy(io.Discard, c)
		return
	}

	log.Printf("[GO] TCP request (HY2): %s", req.Addr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cs, err := ch.Open(ctx, req.Host, req.Port)
	cancel()
	if err != nil {
		log.Printf("[GO] ch.Open (HY2) failed for %s: %v", req.Addr(), err)
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
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(cs, c, buf)
		_ = cs.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(c, cs, buf)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}