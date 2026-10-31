package proxy

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
)

func TestParseOpenPayloadIPv4(t *testing.T) {
	p := []byte{0x01, 127, 0, 0, 1, 0x1F, 0x90} // 127.0.0.1:8080
	host, port, err := parseOpenPayload(p)
	if err != nil {
		t.Fatalf("parseOpenPayload: %v", err)
	}
	if host != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %s:%d", host, port)
	}
}

func TestParseOpenPayloadIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1").To16()
	p := []byte{0x04}
	p = append(p, ip...)
	p = append(p, 0x01, 0xBB) // port 443

	host, port, err := parseOpenPayload(p)
	if err != nil {
		t.Fatalf("parseOpenPayload: %v", err)
	}
	if host != "2001:db8::1" || port != 443 {
		t.Fatalf("got %s:%d", host, port)
	}
}

func TestParseOpenPayloadDomain(t *testing.T) {
	domain := "example.com"
	p := []byte{0x03, byte(len(domain))}
	p = append(p, []byte(domain)...)
	p = append(p, 0x00, 0x50) // port 80

	host, port, err := parseOpenPayload(p)
	if err != nil {
		t.Fatalf("parseOpenPayload: %v", err)
	}
	if host != domain || port != 80 {
		t.Fatalf("got %s:%d", host, port)
	}
}

func TestParseOpenPayloadErrors(t *testing.T) {
	cases := [][]byte{
		{},                  // empty
		{0x01},              // ipv4 truncated
		{0x01, 1, 2, 3},     // ipv4 truncated (no port)
		{0x04, 1, 2, 3},     // ipv6 truncated
		{0x03},              // domain no len
		{0x03, 5, 'a', 'b'}, // domain shorter than len
		{0x99, 0, 0},        // unknown atyp
	}
	for i, p := range cases {
		if _, _, err := parseOpenPayload(p); err == nil {
			t.Errorf("case %d should error", i)
		}
	}
}

func TestEncodeOpenOKIPv4(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
	p := encodeOpenOK(addr)
	if p[0] != 0x01 {
		t.Fatalf("atyp = 0x%02x, want 0x01", p[0])
	}
	if port := uint16(p[5])<<8 | uint16(p[6]); port != 1080 {
		t.Fatalf("port = %d, want 1080", port)
	}
}

func TestEncodeOpenOKNil(t *testing.T) {
	p := encodeOpenOK(nil)
	if len(p) != 7 || p[0] != 0x01 {
		t.Fatalf("nil addr should produce 0.0.0.0:0, got %v", p)
	}
}

func TestEncodeResetPayload(t *testing.T) {
	p := encodeResetPayload(ghostmux.CodeDialFailed, "nope")
	if len(p) < 2 {
		t.Fatal("payload too short")
	}
	code := ghostmux.ErrorCode(uint16(p[0])<<8 | uint16(p[1]))
	if code != ghostmux.CodeDialFailed {
		t.Fatalf("code = %v, want DIAL_FAILED", code)
	}
	if string(p[2:]) != "nope" {
		t.Fatalf("msg = %q, want %q", p[2:], "nope")
	}
}

// setupEndpoint создаёт endpoint с pipe и loopback origin.
// Возвращает handler, conn, и функцию для отправки кадров
// "от клиента" в сервер, и приёмник кадров "от сервера".
func setupEndpoint(t *testing.T, policy SSRFPolicy) (
	*EndpointHandler,
	func(*ghostmux.Frame) error,
	func() (*ghostmux.Frame, error),
	func(),
) {
	t.Helper()

	clientSide, serverSide := net.Pipe()

	sess := ghostmux.NewSession()
	_ = sess.BeginNegotiation()
	_ = sess.AcceptRemoteSettings(ghostmux.DefaultSettings())

	sched := ghostmux.NewScheduler(0)
	conn := ghostmux.NewConn(serverSide, sess, sched, 4)

	dial := NewTargetDialer(policy, 2*time.Second)
	handler := NewEndpointHandler(sess, conn, dial, DefaultServerConfig())

	conn.Start(handler)

	// Отправка "от клиента": пишем кадр напрямую в clientSide.
	sendFromClient := func(f *ghostmux.Frame) error {
		var hdr [ghostmux.FrameHeaderSize]byte
		if err := f.Encode(hdr[:]); err != nil {
			return err
		}
		buf := append(hdr[:], f.Payload...)
		_, err := clientSide.Write(buf)
		return err
	}

	// Чтение "на клиенте".
	recv := func() (*ghostmux.Frame, error) {
		return ghostmux.ReadFrame(clientSide)
	}

	cleanup := func() {
		clientSide.Close()
		conn.Close()
		_ = conn.Wait()
	}
	return handler, sendFromClient, recv, cleanup
}

// loopbackOrigin поднимает TCP-эхо на 127.0.0.1:0.
func loopbackOrigin(t *testing.T, resp []byte) (string, uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				_ = n
				_, _ = conn.Write(resp)
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, b := range []byte(portStr) {
		port = port*10 + uint16(b-'0')
	}
	return host, port, func() { ln.Close() }
}

func TestEndpointOnFrameRejectsUnknown(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, DefaultSSRFPolicy())
	defer cleanup()

	// SETTINGS no-op, но не должен падать
	if err := h.OnFrame(&ghostmux.Frame{Type: ghostmux.FrameSettings}); err != nil {
		t.Fatalf("SETTINGS should be no-op: %v", err)
	}
	// OpenErr на серверную сторону — неожиданно
	err := h.OnFrame(&ghostmux.Frame{Type: ghostmux.FrameOpenErr, StreamID: 1})
	if err == nil {
		t.Fatal("unexpected frame type should error")
	}
}

func TestEndpointOpenRejectsStreamIDZero(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, DefaultSSRFPolicy())
	defer cleanup()

	err := h.OnFrame(&ghostmux.Frame{Type: ghostmux.FrameOpen, StreamID: 0})
	if err == nil {
		t.Fatal("OPEN with stream_id 0 should error")
	}
}

func TestEndpointOpenLoopbackDenied(t *testing.T) {
	_, send, recv, cleanup := setupEndpoint(t, DefaultSSRFPolicy())
	defer cleanup()

	// OPEN к 127.0.0.1
	payload := []byte{0x01, 127, 0, 0, 1, 0x00, 0x50}
	if err := send(&ghostmux.Frame{
		Type:     ghostmux.FrameOpen,
		StreamID: 1,
		Payload:  payload,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Ждём OPEN_ERR.
	_ = recv // silence
	f, err := recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if f.Type != ghostmux.FrameOpenErr {
		t.Fatalf("frame type = 0x%02x, want OPEN_ERR", uint8(f.Type))
	}
	if f.StreamID != 1 {
		t.Fatalf("stream_id = %d, want 1", f.StreamID)
	}
	// код должен быть DIAL_FAILED или ADDRESS_DENIED (сейчас DialFailed)
	code := ghostmux.ErrorCode(uint16(f.Payload[0])<<8 | uint16(f.Payload[1]))
	if code != ghostmux.CodeDialFailed {
		t.Fatalf("code = %v, want DIAL_FAILED", code)
	}
}

func TestEndpointOpenLoopbackAccepted(t *testing.T) {
	h, send, recv, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	host, port, stopOrigin := loopbackOrigin(t, []byte("hello"))
	defer stopOrigin()

	ip := net.ParseIP(host).To4()
	payload := []byte{0x01}
	payload = append(payload, ip...)
	payload = append(payload, byte(port>>8), byte(port))

	if err := send(&ghostmux.Frame{
		Type:     ghostmux.FrameOpen,
		StreamID: 3,
		Payload:  payload,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Должны получить OPEN_OK.
	f, err := recv()
	if err != nil {
		t.Fatalf("recv OPEN_OK: %v", err)
	}
	if f.Type != ghostmux.FrameOpenOK {
		t.Fatalf("type = 0x%02x, want OPEN_OK", uint8(f.Type))
	}
	if f.StreamID != 3 {
		t.Fatalf("stream_id = %d, want 3", f.StreamID)
	}
	_ = h
}

func TestEndpointDuplicateOpen(t *testing.T) {
	h, send, recv, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	host, port, stopOrigin := loopbackOrigin(t, []byte("x"))
	defer stopOrigin()
	ip := net.ParseIP(host).To4()
	payload := []byte{0x01}
	payload = append(payload, ip...)
	payload = append(payload, byte(port>>8), byte(port))

	_ = send(&ghostmux.Frame{Type: ghostmux.FrameOpen, StreamID: 5, Payload: payload})
	f1, _ := recv()
	if f1 == nil || f1.Type != ghostmux.FrameOpenOK {
		t.Fatalf("first OPEN should succeed, got %v", f1)
	}
	_ = h

	// Второй OPEN с тем же id — должен получить OPEN_ERR.
	_ = send(&ghostmux.Frame{Type: ghostmux.FrameOpen, StreamID: 5, Payload: payload})
	f2, _ := recv()
	if f2 == nil || f2.Type != ghostmux.FrameOpenErr {
		t.Fatalf("duplicate OPEN should fail, got %v", f2)
	}
}

func TestEndpointDataForUnknownStream(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	err := h.OnFrame(&ghostmux.Frame{
		Type:     ghostmux.FrameData,
		StreamID: 999,
		Payload:  []byte("x"),
	})
	if err == nil {
		t.Fatal("DATA for unknown stream should error")
	}
}

func TestEndpointFinIdempotent(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	// FIN для неизвестного stream — не должно падать.
	if err := h.OnFrame(&ghostmux.Frame{Type: ghostmux.FrameFin, StreamID: 7}); err != nil {
		t.Fatalf("FIN for unknown stream: %v", err)
	}
}

func TestEndpointResetIdempotent(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	if err := h.OnFrame(&ghostmux.Frame{Type: ghostmux.FrameReset, StreamID: 7}); err != nil {
		t.Fatalf("RESET for unknown stream: %v", err)
	}
}

func TestEndpointDropStreamIdempotent(t *testing.T) {
	h, _, _, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	h.dropStream(42)
	h.dropStream(42) // не должно паниковать
}

func TestEndpointMalformedOpenPayload(t *testing.T) {
	h, send, recv, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	// Пустой payload — parseOpenPayload вернёт ошибку.
	_ = send(&ghostmux.Frame{Type: ghostmux.FrameOpen, StreamID: 9, Payload: []byte{}})
	_ = h

	f, err := recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if f.Type != ghostmux.FrameOpenErr {
		t.Fatalf("malformed OPEN should return OPEN_ERR, got 0x%02x", uint8(f.Type))
	}
}

func TestEndpointRoundTripData(t *testing.T) {
	h, send, recv, cleanup := setupEndpoint(t, BenchmarkSSRFPolicy())
	defer cleanup()

	// Origin шлёт ответ после получения данных.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, b := range []byte(portStr) {
		port = port*10 + uint16(b-'0')
	}
	ip := net.ParseIP(host).To4()
	payload := []byte{0x01}
	payload = append(payload, ip...)
	payload = append(payload, byte(port>>8), byte(port))

	// OPEN
	if err := send(&ghostmux.Frame{Type: ghostmux.FrameOpen, StreamID: 11, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if f, _ := recv(); f == nil || f.Type != ghostmux.FrameOpenOK {
		t.Fatalf("no OPEN_OK: %v", f)
	}

	// DATA "ping"
	if err := send(&ghostmux.Frame{
		Type:     ghostmux.FrameData,
		StreamID: 11,
		Payload:  []byte("ping"),
	}); err != nil {
		t.Fatal(err)
	}

	// Ожидаем DATA обратно с "echo:ping"
	deadline := time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		f, err := recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if f.Type == ghostmux.FrameData && f.StreamID == 11 {
			got = append(got, f.Payload...)
			if bytes.Equal(got, []byte("echo:ping")) {
				break
			}
		}
		if f.Type == ghostmux.FrameFin {
			break
		}
	}

	if !bytes.Equal(got, []byte("echo:ping")) {
		t.Fatalf("got %q, want %q", got, "echo:ping")
	}
	_ = h
}
