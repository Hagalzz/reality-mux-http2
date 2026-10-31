package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
)

// EndpointHandler — серверная сторона GHOST.
type EndpointHandler struct {
	sess   *ghostmux.Session
	conn   *ghostmux.Conn
	dial   *TargetDialer
	policy SSRFPolicy

	dialTimeout time.Duration

	mu      sync.Mutex
	streams map[uint32]*serverStream
	openSem chan struct{}
	closed  bool
}

// ServerConfig — параметры серверного endpoint.
type ServerConfig struct {
	MaxConcurrentOpens int
	DialTimeout        time.Duration
}

// DefaultServerConfig — стартовые значения.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		MaxConcurrentOpens: 256,
		DialTimeout:        1 * time.Second,
	}
}

// NewEndpointHandler создаёт handler.
func NewEndpointHandler(
	sess *ghostmux.Session,
	conn *ghostmux.Conn,
	dial *TargetDialer,
	cfg ServerConfig,
) *EndpointHandler {
	if cfg.MaxConcurrentOpens <= 0 {
		cfg.MaxConcurrentOpens = 32
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &EndpointHandler{
		sess:        sess,
		conn:        conn,
		dial:        dial,
		policy:      dial.Policy(),
		dialTimeout: cfg.DialTimeout,
		streams:     make(map[uint32]*serverStream),
		openSem:     make(chan struct{}, cfg.MaxConcurrentOpens),
	}
}

type serverStream struct {
	id       uint32
	stream   *ghostmux.Stream
	outbound net.Conn
	isUDP    bool // Флаг UDP-over-TCP

	queue chan []byte
	closeCh chan struct{}
	closed  sync.Once
	wg sync.WaitGroup
}

func (ss *serverStream) shutdown() {
	ss.closed.Do(func() {
		close(ss.closeCh)
		if ss.outbound != nil {
			ss.outbound.Close()
		}
	})
}

func (h *EndpointHandler) OnFrame(f *ghostmux.Frame) error {
	switch f.Type {
	case ghostmux.FrameOpen:
		frameCopy := *f
		frameCopy.Payload = append([]byte(nil), f.Payload...)
		go func(frame *ghostmux.Frame) { _ = h.handleOpen(frame) }(&frameCopy)
		return nil
	case ghostmux.FrameData:
		return h.handleData(f)
	case ghostmux.FrameFin:
		return h.handleFin(f)
	case ghostmux.FrameReset:
		return h.handleReset(f)
	case ghostmux.FrameSettings, ghostmux.FrameSettingsAck,
		ghostmux.FrameGoAway, ghostmux.FrameWindowUpdate,
		ghostmux.FramePing, ghostmux.FramePong:
		return nil
	default:
		return ghostmux.NewError(ghostmux.CodeProtocolError,
			"endpoint: unexpected frame 0x%02x", uint8(f.Type))
	}
}

func (h *EndpointHandler) handleOpen(f *ghostmux.Frame) error {
	if f.StreamID == ghostmux.SessionStreamID {
		return ghostmux.NewError(ghostmux.CodeProtocolError,
			"endpoint: OPEN with stream_id 0")
	}

	host, port, err := parseOpenPayload(f.Payload)
	if err != nil {
		h.sendOpenErr(f.StreamID, ghostmux.CodeProtocolError, err.Error())
		return nil
	}

	isUDP := (f.Flags & 0x01) != 0

	h.mu.Lock()
	if _, exists := h.streams[f.StreamID]; exists {
		h.mu.Unlock()
		h.sendOpenErr(f.StreamID, ghostmux.CodeProtocolError, "duplicate OPEN")
		return nil
	}
	st, _ := ghostmux.NewStream(f.StreamID)
	_ = st.MarkOpening()
	_ = st.MarkOpened()

	ss := &serverStream{
		id:      f.StreamID,
		stream:  st,
		isUDP:   isUDP,
		queue:   make(chan []byte, 1024),
		closeCh: make(chan struct{}),
	}
	h.streams[f.StreamID] = ss
	h.mu.Unlock()

	select {
	case h.openSem <- struct{}{}:
	default:
		h.dropStream(f.StreamID)
		h.sendOpenErr(f.StreamID, ghostmux.CodeStreamLimit, "too many pending opens")
		return nil
	}

	go func() {
		defer func() { <-h.openSem }()

		ctx, cancel := context.WithTimeout(context.Background(), h.dialTimeout)
		defer cancel()

		var outbound net.Conn
		var err error

		if isUDP {
			// ДЛЯ UDP: Открываем UDP-сокет
			outbound, err = net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(int(port))), h.dialTimeout)
		} else {
			// ДЛЯ TCP: Обычный dial
			outbound, err = h.dial.Dial(ctx, host, port)
		}

		if err != nil {
			h.dropStream(f.StreamID)
			h.sendOpenErr(f.StreamID, ghostmux.CodeDialFailed, err.Error())
			return
		}

		h.mu.Lock()
		cur, ok := h.streams[f.StreamID]
		if !ok || cur != ss {
			h.mu.Unlock()
			outbound.Close()
			return
		}
		ss.outbound = outbound
		h.mu.Unlock()

		openOK := &ghostmux.Frame{
			Type:     ghostmux.FrameOpenOK,
			StreamID: f.StreamID,
			Payload:  encodeOpenOK(outbound.LocalAddr()),
		}
		if err := h.conn.WriteFrame(openOK); err != nil {
			h.dropStream(f.StreamID)
			return
		}

		ss.wg.Add(2)
		go h.writerLoop(ss)
		go h.readerLoop(ss)
	}()

	return nil
}

// chanReader превращает канал байтов в io.Reader для io.ReadFull
type chanReader struct {
	ch  <-chan []byte
	buf []byte
}

func (r *chanReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		var ok bool
		r.buf, ok = <-r.ch
		if !ok || r.buf == nil {
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// writerLoop: queue -> outbound.
func (h *EndpointHandler) writerLoop(ss *serverStream) {
	defer ss.wg.Done()

	if ss.isUDP {
		// ДЛЯ UDP: читаем 2-байтовый префикс длины, затем сам пакет
		cr := &chanReader{ch: ss.queue}
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(cr, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if length == 0 {
				continue // Пустой UDP-пакет
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(cr, payload); err != nil {
				return
			}
			if _, err := ss.outbound.Write(payload); err != nil {
				h.dropStream(ss.id)
				return
			}
		}
	} else {
		// ДЛЯ TCP: обычная запись
		for {
			select {
			case <-ss.closeCh:
				return
			case data, ok := <-ss.queue:
				if !ok {
					return
				}
				if data == nil {
					if tc, ok := ss.outbound.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					continue
				}
				if _, err := ss.outbound.Write(data); err != nil {
					h.dropStream(ss.id)
					return
				}
			}
		}
	}
}

// readerLoop: outbound -> session как DATA.
func (h *EndpointHandler) readerLoop(ss *serverStream) {
	defer ss.wg.Done()
	buf := make([]byte, ghostmux.MaxDataPayload)
	for {
		select {
		case <-ss.closeCh:
			return
		default:
		}

		n, err := ss.outbound.Read(buf)
		if n > 0 {
			var payload []byte
			if ss.isUDP {
				// ДЛЯ UDP: добавляем 2-байтовый префикс длины
				payload = make([]byte, 2+n)
				binary.BigEndian.PutUint16(payload, uint16(n))
				copy(payload[2:], buf[:n])
			} else {
				// ДЛЯ TCP: просто копируем данные
				payload = make([]byte, n)
				copy(payload, buf[:n])
			}

			f := &ghostmux.Frame{
				Type:     ghostmux.FrameData,
				StreamID: ss.id,
				Payload:  payload,
			}
			if werr := h.conn.WriteFrame(f); werr != nil {
				h.dropStream(ss.id)
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				_ = h.conn.WriteFrame(&ghostmux.Frame{
					Type:     ghostmux.FrameFin,
					StreamID: ss.id,
				})
			} else {
				_ = h.conn.WriteFrame(&ghostmux.Frame{
					Type:     ghostmux.FrameReset,
					StreamID: ss.id,
					Payload:  encodeResetPayload(ghostmux.CodeInternal, err.Error()),
				})
			}
			h.dropStream(ss.id)
			return
		}
	}
}

func (h *EndpointHandler) handleData(f *ghostmux.Frame) error {
	h.mu.Lock()
	ss, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return ghostmux.NewError(ghostmux.CodeProtocolError,
			"endpoint: DATA for unknown stream %d", f.StreamID)
	}

	cp := make([]byte, len(f.Payload))
	copy(cp, f.Payload)

	select {
	case ss.queue <- cp:
		return nil
	case <-ss.closeCh:
		return nil
	default:
		_ = h.conn.WriteFrame(&ghostmux.Frame{
			Type:     ghostmux.FrameReset,
			StreamID: f.StreamID,
			Payload:  encodeResetPayload(ghostmux.CodeFlowControl, "queue overflow"),
		})
		h.dropStream(f.StreamID)
		return nil
	}
}

func (h *EndpointHandler) handleFin(f *ghostmux.Frame) error {
	h.mu.Lock()
	ss, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	_ = ss.stream.MarkRemoteFin()

	select {
	case ss.queue <- nil:
	case <-ss.closeCh:
	default:
		go func() {
			select {
			case ss.queue <- nil:
			case <-ss.closeCh:
			}
		}()
	}
	return nil
}

func (h *EndpointHandler) handleReset(f *ghostmux.Frame) error {
	h.dropStream(f.StreamID)
	return nil
}

func (h *EndpointHandler) dropStream(id uint32) *serverStream {
	h.mu.Lock()
	ss, ok := h.streams[id]
	if ok {
		delete(h.streams, id)
	}
	h.mu.Unlock()
	if !ok {
		return nil
	}
	ss.shutdown()
	return ss
}

func (h *EndpointHandler) sendOpenErr(id uint32, code ghostmux.ErrorCode, msg string) {
	_ = h.conn.WriteFrame(&ghostmux.Frame{
		Type:     ghostmux.FrameOpenErr,
		StreamID: id,
		Payload:  encodeResetPayload(code, msg),
	})
}

func parseOpenPayload(p []byte) (string, uint16, error) {
	if len(p) < 1 {
		return "", 0, fmt.Errorf("empty OPEN payload")
	}
	atyp := p[0]
	var host string
	var off int

	switch atyp {
	case 0x01:
		if len(p) < 1+4+2 {
			return "", 0, fmt.Errorf("OPEN ipv4 truncated")
		}
		host = net.IP(p[1:5]).String()
		off = 5
	case 0x04:
		if len(p) < 1+16+2 {
			return "", 0, fmt.Errorf("OPEN ipv6 truncated")
		}
		host = net.IP(p[1:17]).String()
		off = 17
	case 0x03:
		if len(p) < 2 {
			return "", 0, fmt.Errorf("OPEN domain truncated")
		}
		dlen := int(p[1])
		if len(p) < 2+dlen+2 {
			return "", 0, fmt.Errorf("OPEN domain truncated")
		}
		host = string(p[2 : 2+dlen])
		off = 2 + dlen
	default:
		return "", 0, fmt.Errorf("OPEN unknown atyp 0x%02x", atyp)
	}

	port := uint16(p[off])<<8 | uint16(p[off+1])
	return host, port, nil
}

func encodeOpenOK(addr net.Addr) []byte {
	if addr == nil {
		return []byte{0x01, 0, 0, 0, 0, 0, 0}
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return []byte{0x01, 0, 0, 0, 0, 0, 0}
	}
	var port uint16
	for _, b := range []byte(portStr) {
		if b < '0' || b > '9' {
			break
		}
		port = port*10 + uint16(b-'0')
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return []byte{0x01, 0, 0, 0, 0, byte(port >> 8), byte(port)}
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte{0x01}, append(v4, byte(port>>8), byte(port))...)
	}
	v6 := ip.To16()
	return append([]byte{0x04}, append(v6, byte(port>>8), byte(port))...)
}

func encodeResetPayload(code ghostmux.ErrorCode, msg string) []byte {
	out := []byte{byte(code >> 8), byte(code)}
	out = append(out, []byte(msg)...)
	return out
}