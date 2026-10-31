package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
)

// ClientHandler — клиентская сторона GHOST.
type ClientHandler struct {
	conn *ghostmux.Conn
	sess *ghostmux.Session

	mu      sync.Mutex
	streams map[uint32]*ClientStream
	closed  bool

	err error
}

// ClientStream — один логический поток на клиенте.
type ClientStream struct {
	id     uint32
	parent *ClientHandler

	openResult chan error
	dataCh     chan []byte
	finCh      chan struct{}
	resetCh    chan struct{}

	pendMu  sync.Mutex
	pending []byte

	closeOnce sync.Once
	state     int
	stateMu   sync.Mutex
}

const (
	csOpening = iota
	csOpened
	csLocalFin
	csClosed
)

// NewClientHandler создаёт клиентский обработчик поверх conn.
func NewClientHandler(conn *ghostmux.Conn, sess *ghostmux.Session) *ClientHandler {
	h := &ClientHandler{
		conn:    conn,
		sess:    sess,
		streams: make(map[uint32]*ClientStream),
	}
	
	go func() {
		<-conn.Done()
		h.Fail(errors.New("ghostmux connection closed"))
	}()
	
	return h
}

func (h *ClientHandler) Fail(err error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	h.err = err
	streams := make([]*ClientStream, 0, len(h.streams))
	for _, cs := range h.streams {
		streams = append(streams, cs)
	}
	h.mu.Unlock()

	for _, cs := range streams {
		cs.closeOnce.Do(func() {
			close(cs.resetCh)
			close(cs.dataCh)
		})
		select {
		case cs.openResult <- err:
		default:
		}
	}
}

func (h *ClientHandler) OnFrame(f *ghostmux.Frame) error {
	switch f.Type {
	case ghostmux.FrameOpenOK:
		return h.handleOpenOK(f)
	case ghostmux.FrameOpenErr:
		return h.handleOpenErr(f)
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
			"client: unexpected frame 0x%02x", uint8(f.Type))
	}
}

// OpenUDP открывает UDP-ассоциацию через TCP-мультиплексор
func (h *ClientHandler) OpenUDP(ctx context.Context, host string, port uint16) (*ClientStream, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("client: handler closed")
	}
	if h.err != nil {
		err := h.err
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	id, err := h.sess.NextStreamID()
	if err != nil {
		return nil, fmt.Errorf("next stream id: %w", err)
	}

	cs := &ClientStream{
		id:         id,
		parent:     h,
		openResult: make(chan error, 1),
		dataCh:     make(chan []byte, 512),
		finCh:      make(chan struct{}),
		resetCh:    make(chan struct{}),
		state:      csOpening,
	}

	h.mu.Lock()
	h.streams[id] = cs
	h.mu.Unlock()

	if err := h.conn.RegisterStream(id, 2*1024*1024, 2048); err != nil {
		h.dropStream(id)
		return nil, fmt.Errorf("register stream: %w", err)
	}

	payload, err := encodeOpenPayload(host, port)
	if err != nil {
		h.dropStream(id)
		return nil, err
	}

	f := &ghostmux.Frame{
		Type:     ghostmux.FrameOpen,
		Flags:    0x01, // ФЛАГ UDP!
		StreamID: id,
		Payload:  payload,
	}
	if err := h.conn.WriteFrame(f); err != nil {
		h.dropStream(id)
		return nil, fmt.Errorf("write OPEN_UDP: %w", err)
	}

	select {
	case err := <-cs.openResult:
		if err != nil {
			h.dropStream(id)
			return nil, err
		}
		cs.stateMu.Lock()
		cs.state = csOpened
		cs.stateMu.Unlock()
		return cs, nil
	case <-ctx.Done():
		h.dropStream(id)
		_ = h.conn.WriteFrame(&ghostmux.Frame{
			Type:     ghostmux.FrameReset,
			StreamID: id,
		})
		return nil, ctx.Err()
	case <-cs.resetCh:
		return nil, errors.New("client: stream reset before open")
	}
}

func (h *ClientHandler) Open(ctx context.Context, host string, port uint16) (*ClientStream, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("client: handler closed")
	}
	if h.err != nil {
		err := h.err
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	id, err := h.sess.NextStreamID()
	if err != nil {
		return nil, fmt.Errorf("next stream id: %w", err)
	}

	cs := &ClientStream{
		id:         id,
		parent:     h,
		openResult: make(chan error, 1),
		dataCh:     make(chan []byte, 512),
		finCh:      make(chan struct{}),
		resetCh:    make(chan struct{}),
		state:      csOpening,
	}

	h.mu.Lock()
	h.streams[id] = cs
	h.mu.Unlock()

	if err := h.conn.RegisterStream(id, 2*1024*1024, 2048); err != nil {
		h.dropStream(id)
		return nil, fmt.Errorf("register stream: %w", err)
	}

	payload, err := encodeOpenPayload(host, port)
	if err != nil {
		h.dropStream(id)
		return nil, err
	}

	f := &ghostmux.Frame{
		Type:     ghostmux.FrameOpen,
		StreamID: id,
		Payload:  payload,
	}
	if err := h.conn.WriteFrame(f); err != nil {
		h.dropStream(id)
		return nil, fmt.Errorf("write OPEN: %w", err)
	}

	select {
	case err := <-cs.openResult:
		if err != nil {
			h.dropStream(id)
			return nil, err
		}
		cs.stateMu.Lock()
		cs.state = csOpened
		cs.stateMu.Unlock()
		return cs, nil
	case <-ctx.Done():
		h.dropStream(id)
		_ = h.conn.WriteFrame(&ghostmux.Frame{
			Type:     ghostmux.FrameReset,
			StreamID: id,
		})
		return nil, ctx.Err()
	case <-cs.resetCh:
		return nil, errors.New("client: stream reset before open")
	}
}

func (cs *ClientStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	cs.stateMu.Lock()
	state := cs.state
	cs.stateMu.Unlock()
	if state >= csLocalFin {
		return 0, errors.New("client stream: write after close")
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > ghostmux.MaxDataPayload {
			chunk = chunk[:ghostmux.MaxDataPayload]
		}
		cp := make([]byte, len(chunk))
		copy(cp, chunk)

		f := &ghostmux.Frame{
			Type:     ghostmux.FrameData,
			StreamID: cs.id,
			Payload:  cp,
		}
		if err := cs.parent.conn.WriteData(cs.id, f); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (cs *ClientStream) Read(p []byte) (int, error) {
	cs.pendMu.Lock()
	if len(cs.pending) > 0 {
		n := copy(p, cs.pending)
		if n == len(cs.pending) {
			cs.pending = nil
		} else {
			cs.pending = cs.pending[n:]
		}
		cs.pendMu.Unlock()
		return n, nil
	}
	cs.pendMu.Unlock()

	select {
	case data, ok := <-cs.dataCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			cs.pendMu.Lock()
			cs.pending = append(cs.pending, data[n:]...)
			cs.pendMu.Unlock()
		}
		return n, nil
	case <-cs.resetCh:
		return 0, errors.New("client stream: reset")
	}
}

func (cs *ClientStream) CloseWrite() error {
	cs.stateMu.Lock()
	if cs.state >= csLocalFin {
		cs.stateMu.Unlock()
		return nil
	}
	cs.state = csLocalFin
	cs.stateMu.Unlock()

	return cs.parent.conn.WriteData(cs.id, &ghostmux.Frame{
		Type:     ghostmux.FrameFin,
		StreamID: cs.id,
	})
}

func (cs *ClientStream) Close() error {
	cs.stateMu.Lock()
	if cs.state >= csClosed {
		cs.stateMu.Unlock()
		return nil
	}
	cs.state = csClosed
	cs.stateMu.Unlock()

	_ = cs.parent.conn.WriteFrame(&ghostmux.Frame{
		Type:     ghostmux.FrameReset,
		StreamID: cs.id,
	})
	cs.parent.dropStream(cs.id)
	return nil
}

func (cs *ClientStream) ID() uint32 { return cs.id }

func (h *ClientHandler) handleOpenOK(f *ghostmux.Frame) error {
	h.mu.Lock()
	cs, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	select {
	case cs.openResult <- nil:
	default:
	}
	return nil
}

func (h *ClientHandler) handleOpenErr(f *ghostmux.Frame) error {
	h.mu.Lock()
	cs, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	msg := "open error"
	if len(f.Payload) >= 2 {
		code := ghostmux.ErrorCode(uint16(f.Payload[0])<<8 | uint16(f.Payload[1]))
		if len(f.Payload) > 2 {
			msg = fmt.Sprintf("%s: %s", code, string(f.Payload[2:]))
		} else {
			msg = code.String()
		}
	}
	select {
	case cs.openResult <- errors.New(msg):
	default:
	}
	h.dropStream(f.StreamID)
	return nil
}

func (h *ClientHandler) handleData(f *ghostmux.Frame) error {
	h.mu.Lock()
	cs, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}

	cp := make([]byte, len(f.Payload))
	copy(cp, f.Payload)

	select {
	case cs.dataCh <- cp:
		return nil
	default:
		_ = h.conn.WriteFrame(&ghostmux.Frame{
			Type:     ghostmux.FrameReset,
			StreamID: f.StreamID,
		})
		h.dropStream(f.StreamID)
		return nil
	}
}

func (h *ClientHandler) handleFin(f *ghostmux.Frame) error {
	h.mu.Lock()
	cs, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}

	cs.closeOnce.Do(func() {
		close(cs.dataCh)
		close(cs.finCh)
	})

	cs.stateMu.Lock()
	localFin := cs.state >= csLocalFin
	cs.stateMu.Unlock()
	if localFin {
		h.dropStream(f.StreamID)
	}
	return nil
}

func (h *ClientHandler) handleReset(f *ghostmux.Frame) error {
	h.mu.Lock()
	cs, ok := h.streams[f.StreamID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	cs.closeOnce.Do(func() {
		close(cs.resetCh)
		close(cs.dataCh)
	})
	h.dropStream(f.StreamID)
	return nil
}

func (h *ClientHandler) dropStream(id uint32) *ClientStream {
	h.mu.Lock()
	cs, ok := h.streams[id]
	if ok {
		delete(h.streams, id)
	}
	h.mu.Unlock()
	if ok {
		h.sess.DropStream(id)
		h.conn.UnregisterStream(id)
	}
	return cs
}

func (h *ClientHandler) Close() {
	h.Fail(errors.New("client: handler closed"))
}

func encodeOpenPayload(host string, port uint16) ([]byte, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) > 255 {
			return nil, fmt.Errorf("host too long: %d", len(host))
		}
		out := []byte{0x03, byte(len(host))}
		out = append(out, []byte(host)...)
		out = append(out, byte(port>>8), byte(port))
		return out, nil
	}
	if v4 := ip.To4(); v4 != nil {
		out := []byte{0x01}
		out = append(out, v4...)
		out = append(out, byte(port>>8), byte(port))
		return out, nil
	}
	v6 := ip.To16()
	out := []byte{0x04}
	out = append(out, v6...)
	out = append(out, byte(port>>8), byte(port))
	return out, nil
}