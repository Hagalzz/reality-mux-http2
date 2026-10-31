package ghostmux

import (
"bytes"
"errors"
"io"
"net"
"sync"
"sync/atomic"
"testing"
"time"
)

// recordingHandler собирает кадры в памяти. Потокобезопасен.
type recordingHandler struct {
mu     sync.Mutex
frames []*Frame
err    error
}

func (h *recordingHandler) OnFrame(f *Frame) error {
if h.err != nil {
return h.err
}
h.mu.Lock()
defer h.mu.Unlock()
h.frames = append(h.frames, f)
return nil
}

func (h *recordingHandler) count() int {
h.mu.Lock()
defer h.mu.Unlock()
return len(h.frames)
}

func (h *recordingHandler) get(i int) *Frame {
h.mu.Lock()
defer h.mu.Unlock()
return h.frames[i]
}

func TestConnWriteFrameDirect(t *testing.T) {
client, server := net.Pipe()
defer client.Close()
defer server.Close()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)

f := &Frame{Type: FramePing, StreamID: 0, Payload: []byte("hello")}

// WriteFrame напрямую — до Start
go func() {
if err := c.WriteFrame(f); err != nil {
t.Errorf("WriteFrame: %v", err)
}
}()

got, err := ReadFrame(server)
if err != nil {
t.Fatalf("ReadFrame: %v", err)
}
if got.Type != f.Type || !bytes.Equal(got.Payload, f.Payload) {
t.Fatalf("got %+v, want %+v", got, f)
}
}

func TestConnReadLoopDeliversFrames(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)

h := &recordingHandler{}
c.Start(h)
defer c.Close()

// Пишем 3 кадра с другого конца
go func() {
for i := 0; i < 3; i++ {
f := &Frame{Type: FramePing, StreamID: uint32(i), Payload: []byte{byte(i)}}
var hdr [FrameHeaderSize]byte
_ = f.Encode(hdr[:])
buf := append(hdr[:], f.Payload...)
_, _ = server.Write(buf)
}
}()

// Ждём
deadline := time.Now().Add(time.Second)
for h.count() < 3 && time.Now().Before(deadline) {
time.Sleep(5 * time.Millisecond)
}
if h.count() != 3 {
t.Fatalf("handler got %d frames, want 3", h.count())
}
for i := 0; i < 3; i++ {
if h.get(i).StreamID != uint32(i) {
t.Errorf("frame %d stream_id = %d", i, h.get(i).StreamID)
}
}

server.Close()
}

func TestConnWriteLoopFromScheduler(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
_ = sched.RegisterStream(1, 0, 0)

c := NewConn(client, sess, sched, 4)
h := &recordingHandler{}
c.Start(h)
defer c.Close()

// Ставим кадры в scheduler.
go func() {
for i := 0; i < 5; i++ {
f := &Frame{Type: FrameData, StreamID: 1, Payload: []byte{byte(i), byte(i)}}
if err := sched.EnqueueData(1, f); err != nil {
t.Errorf("EnqueueData: %v", err)
return
}
}
}()

// Читаем с другого конца.
got := 0
for got < 5 {
f, err := ReadFrame(server)
if err != nil {
t.Fatalf("ReadFrame after %d frames: %v", got, err)
}
if f.Type != FrameData {
t.Fatalf("frame %d type = %v, want DATA", got, f.Type)
}
got++
}
server.Close()
}

func TestConnBatchPreservesFrameBoundaries(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
_ = sched.RegisterStream(1, 0, 0)

c := NewConn(client, sess, sched, 8)
h := &recordingHandler{}
c.Start(h)
defer c.Close()

// Разные размеры payload
sizes := []int{3, 1, 10, 5, 2}
go func() {
for _, s := range sizes {
f := &Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{'x'}, s)}
_ = sched.EnqueueData(1, f)
}
}()

for i, want := range sizes {
f, err := ReadFrame(server)
if err != nil {
t.Fatalf("frame %d: %v", i, err)
}
if len(f.Payload) != want {
t.Errorf("frame %d payload = %d, want %d", i, len(f.Payload), want)
}
}
server.Close()
}

func TestConnHandlerErrorStopsLoop(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)

boom := errors.New("handler boom")
h := &recordingHandler{err: boom}
c.Start(h)

go func() {
f := &Frame{Type: FramePing}
var hdr [FrameHeaderSize]byte
_ = f.Encode(hdr[:])
_, _ = server.Write(hdr[:])
}()

// Ждём остановки
select {
case <-c.Done():
case <-time.After(2 * time.Second):
t.Fatal("conn did not stop after handler error")
}

if err := c.Wait(); !errors.Is(err, boom) {
t.Fatalf("Wait() = %v, want %v", err, boom)
}
server.Close()
}

func TestConnCloseIdempotent(t *testing.T) {
client, server := net.Pipe()
defer server.Close()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)
c.Start(&recordingHandler{})

if err := c.Close(); err != nil {
t.Fatalf("first Close: %v", err)
}
if err := c.Close(); err != nil {
t.Fatalf("second Close: %v", err)
}

_ = c.Wait()
}

func TestConnClosesScheduler(t *testing.T) {
client, server := net.Pipe()
defer server.Close()

sess := NewSession()
sched := NewScheduler(0)
_ = sched.RegisterStream(1, 0, 0)
c := NewConn(client, sess, sched, 0)
c.Start(&recordingHandler{})

c.Close()
_ = c.Wait()

if !sched.Closed() {
t.Fatal("scheduler should be closed after Conn.Close")
}
}

func TestConnEOFStops(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)
c.Start(&recordingHandler{})

// Закрываем peer — reader получит EOF.
server.Close()

select {
case <-c.Done():
case <-time.After(2 * time.Second):
t.Fatal("conn did not stop on EOF")
}
_ = c.Wait()
}

func TestConnConcurrentEnqueue(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
for i := uint32(1); i <= 4; i++ {
_ = sched.RegisterStream(i, 0, 0)
}
c := NewConn(client, sess, sched, 8)
c.Start(&recordingHandler{})
defer c.Close()

// Дренаж reader — не проверяем содержимое, только что не падает.
var drained int64
stopDrain := make(chan struct{})
go func() {
for {
select {
case <-stopDrain:
return
default:
}
_, err := ReadFrame(server)
if err != nil {
return
}
atomic.AddInt64(&drained, 1)
}
}()

var wg sync.WaitGroup
for i := uint32(1); i <= 4; i++ {
id := i
wg.Add(1)
go func() {
defer wg.Done()
for j := 0; j < 50; j++ {
_ = sched.EnqueueData(id, &Frame{
Type: FrameData, StreamID: id, Payload: []byte("x"),
})
}
}()
}
wg.Wait()
time.Sleep(100 * time.Millisecond)
close(stopDrain)

// Не строгая проверка: главное, что нет гонки и deadlock.
if atomic.LoadInt64(&drained) == 0 {
t.Fatal("no frames were drained")
}
server.Close()
}

func TestConnWriteFrameEncodeError(t *testing.T) {
client, server := net.Pipe()
defer client.Close()
defer server.Close()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)

// FrameData с payload > MaxDataPayload
bad := &Frame{
Type:    FrameData,
Payload: make([]byte, MaxDataPayload+1),
}
if err := c.WriteFrame(bad); err == nil {
t.Fatal("oversized frame should error")
}
}

func TestConnWaitAfterClose(t *testing.T) {
client, server := net.Pipe()

sess := NewSession()
sched := NewScheduler(0)
c := NewConn(client, sess, sched, 0)
c.Start(&recordingHandler{})

go func() {
time.Sleep(20 * time.Millisecond)
c.Close()
}()

done := make(chan error, 1)
go func() {
done <- c.Wait()
}()

select {
case <-done:
case <-time.After(2 * time.Second):
t.Fatal("Wait did not return after Close")
}
_ = server.Close()
}

// silence unused import
var _ = io.EOF
