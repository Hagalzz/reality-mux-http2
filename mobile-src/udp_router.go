package mobile

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

type flowMeta struct {
	IngressID uint32
	Source    netip.AddrPort
	Protocol  uint8
}

type flowKey struct {
	IngressID uint32
	Protocol  uint8
	Source    netip.AddrPort
	Dest      netip.AddrPort
	DestHost  string
}

type datagram struct {
	Payload []byte
	Peer    netip.AddrPort
}

type udpDialer interface {
	Dial(ctx context.Context) (udpTransport, error)
}

type udpTransport interface {
	OpenFlow(ctx context.Context, key flowKey, meta flowMeta) (udpFlow, error)
	Close() error
}

type udpFlow interface {
	Write(ctx context.Context, payload []byte) error
	Read(ctx context.Context) (datagram, error)
	Close() error
}

type udpManager struct {
	transport udpTransport
}

func newUDPManager(transport udpTransport) *udpManager {
	return &udpManager{transport: transport}
}

type fakeUDPTransport struct{}

func (f *fakeUDPTransport) OpenFlow(ctx context.Context, key flowKey, meta flowMeta) (udpFlow, error) {
	return &fakeUDPFlow{ctx: ctx}, nil
}

func (f *fakeUDPTransport) Close() error {
	return nil
}

type fakeUDPFlow struct {
	ctx context.Context
}

func (f *fakeUDPFlow) Write(ctx context.Context, payload []byte) error {
	return nil
}

func (f *fakeUDPFlow) Read(ctx context.Context) (datagram, error) {
	<-ctx.Done()
	return datagram{}, ctx.Err()
}

func (f *fakeUDPFlow) Close() error {
	return nil
}

// --- Реализация для Hysteria 2 ---

type hysteriaTransport struct {
	mu         sync.Mutex
	serverAddr string
	auth       string
	client     client.Client

	udpConns sync.Map
}

func newHysteriaTransport(serverAddr string, auth string, deviceID string) (*hysteriaTransport, error) {
	combinedAuth := auth
	if deviceID != "" {
		combinedAuth = auth + ":" + deviceID
	}

	t := &hysteriaTransport{
		serverAddr: serverAddr,
		auth:       combinedAuth,
	}
	return t, nil
}

func (t *hysteriaTransport) getClient() (client.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	return t.reconnectLocked()
}

func (t *hysteriaTransport) reconnectLocked() (client.Client, error) {
	if t.client != nil {
		t.client.Close()
		t.client = nil
	}

	// Откатили udp4 обратно на udp
	udpAddr, err := net.ResolveUDPAddr("udp", t.serverAddr)
	if err != nil {
		return nil, err
	}

	cfg := &client.Config{
		ServerAddr: udpAddr,
		Auth:       t.auth,
		TLSConfig: client.TLSConfig{
			InsecureSkipVerify: true,
		},
		QUICConfig: client.QUICConfig{
			InitialStreamReceiveWindow:     1024 * 1024 * 8,
			MaxStreamReceiveWindow:         1024 * 1024 * 8,
			InitialConnectionReceiveWindow: 1024 * 1024 * 32,
			MaxConnectionReceiveWindow:     1024 * 1024 * 32,
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
			DisablePathMTUDiscovery:        true,
		},
	}

	c, _, err := client.NewClient(cfg)
	if err == nil {
		t.client = c
		log.Printf("[GO] Hysteria 2 client (re)connected successfully")
	} else {
		log.Printf("[GO] Hysteria 2 client reconnect failed: %v", err)
	}
	return c, err
}

func (t *hysteriaTransport) handleError(c client.Client, err error) {
	if err == nil {
		return
	}
	errStr := err.Error()
	if strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "broken pipe") {
		log.Printf("[GO] Hysteria 2 network error, forcing reconnect: %v", err)
		t.invalidate(c)
	}
}

func (t *hysteriaTransport) invalidate(c client.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == c {
		t.client.Close()
		t.client = nil

		t.udpConns.Range(func(k, v interface{}) bool {
			uConn := v.(*hysteriaUDPConn)
			uConn.mu.Lock()
			if uConn.hyConn != nil {
				uConn.hyConn.Close()
				uConn.hyConn = nil
			}
			uConn.mu.Unlock()
			return true
		})
		t.udpConns = sync.Map{}
	}
}

func (t *hysteriaTransport) OpenFlow(ctx context.Context, key flowKey, meta flowMeta) (udpFlow, error) {
	c, err := t.getClient()
	if err != nil {
		return nil, err
	}

	srcKey := key.Source.String()
	connIface, _ := t.udpConns.LoadOrStore(srcKey, &hysteriaUDPConn{parent: t, client: c})
	uConn := connIface.(*hysteriaUDPConn)

	uConn.mu.Lock()
	defer uConn.mu.Unlock()

	if uConn.hyConn == nil {
		hyConn, err := c.UDP()
		if err != nil {
			t.handleError(c, err)
			return nil, err
		}
		uConn.hyConn = hyConn
		go uConn.readLoop()
	}

	destKey := key.Dest.String()
	if key.DestHost != "" {
		if strings.Contains(key.DestHost, ":") {
			destKey = key.DestHost
		} else {
			destKey = net.JoinHostPort(key.DestHost, strconv.Itoa(int(key.Dest.Port())))
		}
	}

	if flowIface, ok := uConn.flows.Load(destKey); ok {
		return flowIface.(*hysteriaUDPFlow), nil
	}

	flow := &hysteriaUDPFlow{
		parent: uConn,
		dest:   destKey,
		ch:     make(chan datagram, 128),
	}
	uConn.flows.Store(destKey, flow)
	return flow, nil
}

func (t *hysteriaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.udpConns.Range(func(k, v interface{}) bool {
		uConn := v.(*hysteriaUDPConn)
		uConn.mu.Lock()
		if uConn.hyConn != nil {
			uConn.hyConn.Close()
			uConn.hyConn = nil
		}
		uConn.mu.Unlock()
		return true
	})
	t.udpConns = sync.Map{}

	if t.client != nil {
		err := t.client.Close()
		t.client = nil
		return err
	}
	return nil
}

type hysteriaUDPConn struct {
	parent *hysteriaTransport
	client client.Client
	mu     sync.Mutex
	hyConn client.HyUDPConn
	flows  sync.Map
}

func (c *hysteriaUDPConn) readLoop() {
	for {
		c.mu.Lock()
		hyConn := c.hyConn
		c.mu.Unlock()

		if hyConn == nil {
			return
		}

		payload, addrStr, err := hyConn.Receive()
		if err != nil {
			c.mu.Lock()
			c.flows.Range(func(k, v interface{}) bool {
				close(v.(*hysteriaUDPFlow).ch)
				return true
			})
			c.flows = sync.Map{}
			c.hyConn = nil
			c.mu.Unlock()

			c.parent.handleError(c.client, err)
			return
		}

		// Парсим адрес, чтобы gVisor знал, куда вернуть ответ
		peer, err := netip.ParseAddrPort(addrStr)
		if err != nil {
			log.Printf("[GO] failed to parse peer addr: %v", err)
			continue
		}

		var targetFlow *hysteriaUDPFlow

		// 1. Ищем точное совпадение IP:Порт
		c.flows.Range(func(k, v interface{}) bool {
			flow := v.(*hysteriaUDPFlow)
			if k.(string) == addrStr {
				targetFlow = flow
				return false
			}
			return true
		})

		// 2. Если точного совпадения нет (Telegram меняет IP), ищем по порту
		if targetFlow == nil {
			_, targetPort, err := net.SplitHostPort(addrStr)
			if err == nil {
				c.flows.Range(func(k, v interface{}) bool {
					flow := v.(*hysteriaUDPFlow)
					_, flowPort, err := net.SplitHostPort(flow.dest)
					if err == nil && flowPort == targetPort {
						targetFlow = flow
						return false
					}
					return true
				})
			}
		}

		// 3. Фоллбэк: если поток всего один, отдаем ему
		if targetFlow == nil {
			var count int
			c.flows.Range(func(k, v interface{}) bool {
				targetFlow = v.(*hysteriaUDPFlow)
				count++
				return true
			})
			if count != 1 {
				targetFlow = nil
			}
		}

		if targetFlow != nil {
			select {
			// Передаем peer в канал
			case targetFlow.ch <- datagram{Payload: payload, Peer: peer}:
			default:
			}
		}
	}
}

type hysteriaUDPFlow struct {
	parent *hysteriaUDPConn
	dest   string
	ch     chan datagram
}

func (f *hysteriaUDPFlow) Write(ctx context.Context, payload []byte) error {
	f.parent.mu.Lock()
	hyConn := f.parent.hyConn
	f.parent.mu.Unlock()

	if hyConn == nil {
		return errors.New("connection closed")
	}

	err := hyConn.Send(payload, f.dest)
	if err != nil {
		f.parent.parent.handleError(f.parent.client, err)
	}
	return err
}

func (f *hysteriaUDPFlow) Read(ctx context.Context) (datagram, error) {
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

func (f *hysteriaUDPFlow) Close() error {
	f.parent.flows.Delete(f.dest)
	return nil
}

// --- Обертка для TCP через Hysteria 2 ---

type hyStreamWrapper struct {
	net.Conn
}

func (h *hyStreamWrapper) CloseWrite() error {
	if tc, ok := h.Conn.(interface{ CloseWrite() error }); ok {
		return tc.CloseWrite()
	}
	return nil
}

func (t *hysteriaTransport) Open(ctx context.Context, host string, port uint16) (stream, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		c, err := t.getClient()
		if err != nil {
			log.Printf("[GO] Hysteria 2 getClient failed: %v, retrying...", err)
			time.Sleep(1 * time.Second)
			continue
		}

		conn, err := c.TCP(addr)
		if err == nil {
			return &hyStreamWrapper{Conn: conn}, nil
		}

		log.Printf("[GO] Hysteria 2 TCP dial failed: %v, retrying...", err)
		t.handleError(c, err)
		time.Sleep(1 * time.Second)
	}
}

// --- УМНЫЙ РОУТЕР (Smart Transport) ---
// Перехватывает UDP-пакеты: Telegram -> QUIC Fallback, остальное -> Hysteria 2

type smartTransport struct {
	hyTrans   udpTransport
	quicTrans udpTransport
}

func newSmartTransport(hy, quic udpTransport) udpTransport {
	return &smartTransport{hyTrans: hy, quicTrans: quic}
}

func (s *smartTransport) OpenFlow(ctx context.Context, key flowKey, meta flowMeta) (udpFlow, error) {
	ipStr := key.Dest.Addr().String()
	host := key.DestHost
	
	// Проверяем IP-адреса Telegram (91.108.* и 149.154.*) и домены
	isTelegram := strings.HasPrefix(ipStr, "91.108.") || 
		          strings.HasPrefix(ipStr, "149.154.") ||
		          strings.Contains(host, "telegram") ||
		          strings.Contains(host, "t.me")

	if isTelegram {
		log.Printf("[GO] Telegram UDP -> QUIC Fallback: %s", ipStr)
		return s.quicTrans.OpenFlow(ctx, key, meta)
	}
	
	// Все остальное (WhatsApp, игры) - шлем в Hysteria 2
	return s.hyTrans.OpenFlow(ctx, key, meta)
}

func (s *smartTransport) Close() error {
	s.hyTrans.Close()
	s.quicTrans.Close()
	return nil
}