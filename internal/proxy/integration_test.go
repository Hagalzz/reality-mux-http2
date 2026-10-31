package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/ghostmux"
)

// testCluster поднимает полный сетап: client <-> server через net.Pipe
// + loopback origin. Позволяет делать запросы как настоящий клиент.
type testCluster struct {
	t          *testing.T
	clientConn *ghostmux.Conn
	serverConn *ghostmux.Conn
	client     *ClientHandler
	server     *EndpointHandler
	origins    []string
	stop       func()
}

func newTestCluster(t *testing.T) *testCluster {
	t.Helper()

	clientPipe, serverPipe := net.Pipe()

	// Session (общая для обеих сторон — в реальности две, но
	// для unit-теста хватит одной, чтобы валидировать интерфейс).
	clientSess := ghostmux.NewSession()
	_ = clientSess.BeginNegotiation()
	_ = clientSess.AcceptRemoteSettings(ghostmux.DefaultSettings())

	serverSess := ghostmux.NewSession()
	_ = serverSess.BeginNegotiation()
	_ = serverSess.AcceptRemoteSettings(ghostmux.DefaultSettings())

	clientSched := ghostmux.NewScheduler(0)
	serverSched := ghostmux.NewScheduler(0)

	clientConn := ghostmux.NewConn(clientPipe, clientSess, clientSched, 8)
	serverConn := ghostmux.NewConn(serverPipe, serverSess, serverSched, 8)

	clientH := NewClientHandler(clientConn, clientSess)

	dial := NewTargetDialer(BenchmarkSSRFPolicy(), 2*time.Second)
	serverH := NewEndpointHandler(serverSess, serverConn, dial, DefaultServerConfig())

	clientConn.Start(clientH)
	serverConn.Start(serverH)

	tc := &testCluster{
		t:          t,
		clientConn: clientConn,
		serverConn: serverConn,
		client:     clientH,
		server:     serverH,
	}
	tc.stop = func() {
		clientConn.Close()
		serverConn.Close()
		_ = clientConn.Wait()
		_ = serverConn.Wait()
	}
	return tc
}

// echoOrigin поднимает TCP-эхо на loopback. Возвращает host, port.
func (tc *testCluster) echoOrigin() (string, uint16) {
	tc.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tc.t.Fatal(err)
	}
	tc.origins = append(tc.origins, ln.Addr().String())

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, b := range []byte(portStr) {
		port = port*10 + uint16(b-'0')
	}
	return host, port
}

// collectAll читает stream до EOF, возвращает накопленные байты.
func collectAll(cs *ClientStream, deadline time.Duration) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		n, err := cs.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
	return out, fmt.Errorf("timeout after %v, got %d bytes", deadline, len(out))
}

// ==== Тесты ====

func TestIntegrationSingleStreamEcho(t *testing.T) {
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cs, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	payload := []byte("hello, ghost")
	if _, err := cs.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := cs.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := collectAll(cs, 2*time.Second)
	if err != nil {
		t.Fatalf("collectAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestIntegrationOpenLoopbackDenied(t *testing.T) {
	// Отдельный cluster с DefaultSSRFPolicy — loopback отклонён.
	clientPipe, serverPipe := net.Pipe()

	clientSess := ghostmux.NewSession()
	_ = clientSess.BeginNegotiation()
	_ = clientSess.AcceptRemoteSettings(ghostmux.DefaultSettings())

	serverSess := ghostmux.NewSession()
	_ = serverSess.BeginNegotiation()
	_ = serverSess.AcceptRemoteSettings(ghostmux.DefaultSettings())

	clientConn := ghostmux.NewConn(clientPipe, clientSess, ghostmux.NewScheduler(0), 8)
	serverConn := ghostmux.NewConn(serverPipe, serverSess, ghostmux.NewScheduler(0), 8)

	clientH := NewClientHandler(clientConn, clientSess)
	dial := NewTargetDialer(DefaultSSRFPolicy(), 2*time.Second)
	serverH := NewEndpointHandler(serverSess, serverConn, dial, DefaultServerConfig())

	clientConn.Start(clientH)
	serverConn.Start(serverH)

	// Close ДО Wait — иначе Wait никогда не вернётся.
	defer func() {
		clientConn.Close()
		serverConn.Close()
		_ = clientConn.Wait()
		_ = serverConn.Wait()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := clientH.Open(ctx, "127.0.0.1", 9999)
	if err == nil {
		t.Fatal("loopback should be denied by default policy")
	}
}

func TestIntegrationManyStreamsSerial(t *testing.T) {
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cs, err := tc.client.Open(ctx, host, port)
		cancel()
		if err != nil {
			t.Fatalf("stream %d Open: %v", i, err)
		}

		msg := []byte(fmt.Sprintf("msg-%d", i))
		if _, err := cs.Write(msg); err != nil {
			t.Fatalf("stream %d Write: %v", i, err)
		}
		_ = cs.CloseWrite()

		got, err := collectAll(cs, 2*time.Second)
		if err != nil {
			t.Fatalf("stream %d collectAll: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("stream %d got %q, want %q", i, got, msg)
		}
	}
}

func TestIntegrationManyStreamsParallel(t *testing.T) {
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	const N = 16
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cs, err := tc.client.Open(ctx, host, port)
			if err != nil {
				errs <- fmt.Errorf("stream %d Open: %w", i, err)
				return
			}

			msg := bytes.Repeat([]byte{byte('A' + i%26)}, 1024)
			if _, err := cs.Write(msg); err != nil {
				errs <- fmt.Errorf("stream %d Write: %w", i, err)
				return
			}
			_ = cs.CloseWrite()

			got, err := collectAll(cs, 3*time.Second)
			if err != nil {
				errs <- fmt.Errorf("stream %d collectAll: %w", i, err)
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("stream %d mismatch: got %d bytes, want %d",
					i, len(got), len(msg))
				return
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestIntegrationBulkPlusShort(t *testing.T) {
	// Проверяем: длинный bulk-поток не блокирует короткие.
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Открываем bulk stream (256 KB).
	bulk, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("bulk Open: %v", err)
	}
	bulkData := bytes.Repeat([]byte("B"), 256*1024)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := bulk.Write(bulkData); err != nil {
			t.Errorf("bulk Write: %v", err)
			return
		}
		_ = bulk.CloseWrite()
	}()

	// Пока bulk шлёт, короткие стримы должны успевать.
	time.Sleep(50 * time.Millisecond)

	const K = 5
	for i := 0; i < K; i++ {
		sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
		cs, err := tc.client.Open(sctx, host, port)
		scancel()
		if err != nil {
			t.Fatalf("short %d Open: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("short-%d", i))
		if _, err := cs.Write(msg); err != nil {
			t.Fatalf("short %d Write: %v", i, err)
		}
		_ = cs.CloseWrite()
		got, err := collectAll(cs, 2*time.Second)
		if err != nil {
			t.Fatalf("short %d collectAll: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("short %d mismatch: got %q", i, got)
		}
	}

	// Дожидаемся bulk.
	wg.Wait()
	got, err := collectAll(bulk, 5*time.Second)
	if err != nil {
		t.Fatalf("bulk collectAll: %v", err)
	}
	if len(got) != len(bulkData) {
		t.Fatalf("bulk got %d bytes, want %d", len(got), len(bulkData))
	}
}

func TestIntegrationDropStreamDoesNotAffectOthers(t *testing.T) {
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Откроем три stream.
	s1, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}

	// Рвём s2 через RESET.
	_ = s2.Close()

	// s1 и s3 должны работать.
	for _, s := range []*ClientStream{s1, s3} {
		msg := []byte("ok")
		if _, err := s.Write(msg); err != nil {
			t.Fatalf("write after drop: %v", err)
		}
		_ = s.CloseWrite()
		got, err := collectAll(s, 2*time.Second)
		if err != nil {
			t.Fatalf("collectAll after drop: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	}
}

func TestIntegrationSlowReader(t *testing.T) {
	// Origin шлёт 64 KB, клиент читает медленно.
	// Проверяем, что другие стримы работают.
	tc := newTestCluster(t)
	defer tc.stop()

	// Origin шлёт много данных.
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
		_, _ = c.Write(bytes.Repeat([]byte("X"), 64*1024))
		// держим открытым пока клиент читает
		time.Sleep(2 * time.Second)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, b := range []byte(portStr) {
		port = port*10 + uint16(b-'0')
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	slow, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}

	// Открываем быстрый stream к эхо.
	echoHost, echoPort := tc.echoOrigin()
	fast, err := tc.client.Open(ctx, echoHost, echoPort)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("fast")
	if _, err := fast.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = fast.CloseWrite()

	got, err := collectAll(fast, 2*time.Second)
	if err != nil {
		t.Fatalf("fast stream blocked by slow reader: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("fast got %q, want %q", got, msg)
	}

	// Медленно читаем slow — просто чтобы освободить ресурсы.
	buf := make([]byte, 1024)
	deadline := time.Now().Add(3 * time.Second)
	total := 0
	for time.Now().Before(deadline) && total < 64*1024 {
		n, err := slow.Read(buf)
		if n > 0 {
			total += n
		}
		if err != nil {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	_ = slow.Close()
}

func TestIntegrationOpenTimeout(t *testing.T) {
	// Если origin недоступен, OPEN должен вернуть ошибку
	// (либо как OPEN_ERR от сервера, либо как timeout).
	tc := newTestCluster(t)
	defer tc.stop()

	// Несуществующий loopback порт: 1 (никто не слушает).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Benchmark policy разрешает loopback, но dial провалится.
	_, err := tc.client.Open(ctx, "127.0.0.1", 1)
	if err == nil {
		t.Fatal("dial to closed port should fail")
	}
}

func TestIntegrationBidirectionalLargeEcho(t *testing.T) {
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cs, err := tc.client.Open(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}

	// 128 KB в обе стороны
	payload := make([]byte, 128*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	go func() {
		_, _ = cs.Write(payload)
		_ = cs.CloseWrite()
	}()

	got, err := collectAll(cs, 5*time.Second)
	if err != nil {
		t.Fatalf("collectAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d, want %d", len(got), len(payload))
	}
}

func TestIntegrationSequentialReuse(t *testing.T) {
	// Много последовательных стримов на одной сессии.
	tc := newTestCluster(t)
	defer tc.stop()

	host, port := tc.echoOrigin()

	const N = 30
	for i := 0; i < N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cs, err := tc.client.Open(ctx, host, port)
		cancel()
		if err != nil {
			t.Fatalf("iter %d Open: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("m%d", i))
		if _, err := cs.Write(msg); err != nil {
			t.Fatalf("iter %d Write: %v", i, err)
		}
		_ = cs.CloseWrite()
		got, err := collectAll(cs, 2*time.Second)
		if err != nil {
			t.Fatalf("iter %d collectAll: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("iter %d mismatch", i)
		}
	}
}
