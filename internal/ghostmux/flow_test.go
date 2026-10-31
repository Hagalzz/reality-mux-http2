package ghostmux

import (
"errors"
"sync"
"testing"
)

func TestCreditTrackerBasic(t *testing.T) {
c, err := NewCreditTracker(100, 100)
if err != nil {
t.Fatal(err)
}
if c.Available() != 100 || c.Limit() != 100 {
t.Fatalf("init: avail=%d limit=%d", c.Available(), c.Limit())
}

if err := c.Consume(40); err != nil {
t.Fatal(err)
}
if c.Available() != 60 {
t.Fatalf("after Consume(40): avail=%d, want 60", c.Available())
}

if err := c.Consume(60); err != nil {
t.Fatal(err)
}
if c.Available() != 0 {
t.Fatalf("after Consume(60): avail=%d, want 0", c.Available())
}

if err := c.Consume(1); err == nil {
t.Fatal("Consume(1) with 0 avail should error")
}
if c.Available() != 0 {
t.Fatal("failed Consume should not change state")
}
}

func TestCreditTrackerGrantClampsToLimit(t *testing.T) {
c, _ := NewCreditTracker(50, 100)

added, err := c.Grant(30)
if err != nil {
t.Fatal(err)
}
if added != 30 || c.Available() != 80 {
t.Fatalf("after Grant(30): added=%d avail=%d", added, c.Available())
}

added, err = c.Grant(50)
if err != nil {
t.Fatal(err)
}
if added != 20 {
t.Fatalf("Grant should clamp: added=%d, want 20", added)
}
if c.Available() != 100 {
t.Fatalf("avail=%d, want 100 (limit)", c.Available())
}

added, _ = c.Grant(10)
if added != 0 {
t.Fatalf("Grant at limit should add 0, got %d", added)
}
}

func TestCreditTrackerRejectsNegatives(t *testing.T) {
c, _ := NewCreditTracker(100, 100)
if err := c.Consume(-1); err == nil {
t.Fatal("Consume(-1) should error")
}
if _, err := c.Grant(-1); err == nil {
t.Fatal("Grant(-1) should error")
}
}

func TestCreditTrackerInvalidInit(t *testing.T) {
cases := []struct {
initial, limit int64
}{
{-1, 100},
{100, -1},
{200, 100}, // initial > limit
}
for _, c := range cases {
if _, err := NewCreditTracker(c.initial, c.limit); err == nil {
t.Errorf("init(%d,%d) should error", c.initial, c.limit)
}
}
}

func TestFlowControlOpenAndClose(t *testing.T) {
f, err := NewFlowControl(1024, 2048, 512)
if err != nil {
t.Fatal(err)
}

if err := f.OpenStream(0); err == nil {
t.Fatal("OpenStream(0) should error")
}

if err := f.OpenStream(3); err != nil {
t.Fatal(err)
}
if err := f.OpenStream(3); err == nil {
t.Fatal("double OpenStream should error")
}

if got := f.StreamSendAvailable(3); got != 512 {
t.Fatalf("StreamSendAvailable=%d, want 512", got)
}
if got := f.StreamRecvAvailable(3); got != 512 {
t.Fatalf("StreamRecvAvailable=%d, want 512", got)
}

if f.Reserved() != 512 {
t.Fatalf("Reserved=%d, want 512", f.Reserved())
}

f.CloseStream(3)
if f.Reserved() != 0 {
t.Fatalf("after close Reserved=%d, want 0", f.Reserved())
}
if got := f.StreamSendAvailable(3); got != -1 {
t.Fatalf("closed stream avail=%d, want -1", got)
}
}

func TestFlowControlSendReserve(t *testing.T) {
f, _ := NewFlowControl(1024, 1024, 512)
_ = f.OpenStream(1)

if err := f.ReserveSend(1, 100); err != nil {
t.Fatal(err)
}
if f.SessionSendAvailable() != 924 {
t.Fatalf("session=%d, want 924", f.SessionSendAvailable())
}
if f.StreamSendAvailable(1) != 412 {
t.Fatalf("stream=%d, want 412", f.StreamSendAvailable(1))
}

// резервируем больше, чем есть в stream — должен быть rollback
before := f.SessionSendAvailable()
if err := f.ReserveSend(1, 1000); err == nil {
t.Fatal("ReserveSend with insufficient stream credit should error")
}
if f.SessionSendAvailable() != before {
t.Fatalf("rollback failed: session=%d, want %d", f.SessionSendAvailable(), before)
}
}

func TestFlowControlSessionExhaustion(t *testing.T) {
// session window меньше stream window
f, _ := NewFlowControl(100, 1024, 512)
_ = f.OpenStream(1)

if err := f.ReserveSend(1, 80); err != nil {
t.Fatal(err)
}
if err := f.ReserveSend(1, 30); err == nil {
t.Fatal("should fail: session credit exhausted")
}
// session не должен измениться после неудачи
if f.SessionSendAvailable() != 20 {
t.Fatalf("session=%d, want 20", f.SessionSendAvailable())
}
}

func TestFlowControlRecvDeliver(t *testing.T) {
f, _ := NewFlowControl(1024, 1024, 512)
_ = f.OpenStream(1)

if err := f.DeliverRecv(1, 200); err != nil {
t.Fatal(err)
}
if f.SessionRecvAvailable() != 824 {
t.Fatalf("session recv=%d, want 824", f.SessionRecvAvailable())
}
if f.StreamRecvAvailable(1) != 312 {
t.Fatalf("stream recv=%d, want 312", f.StreamRecvAvailable(1))
}

if err := f.DeliverRecv(1, 400); err == nil {
t.Fatal("DeliverRecv over window should error")
}
// rollback проверяем: session не изменился
if f.SessionRecvAvailable() != 824 {
t.Fatalf("rollback failed: session=%d, want 824", f.SessionRecvAvailable())
}
}

func TestFlowControlReleaseRecv(t *testing.T) {
f, _ := NewFlowControl(1024, 1024, 512)
_ = f.OpenStream(1)

_ = f.DeliverRecv(1, 300)

sessAdded, streamAdded := f.ReleaseRecv(1, 300)
if sessAdded != 300 || streamAdded != 300 {
t.Fatalf("ReleaseRecv added sess=%d stream=%d, want 300/300", sessAdded, streamAdded)
}
if f.SessionRecvAvailable() != 1024 {
t.Fatalf("session recv=%d, want 1024", f.SessionRecvAvailable())
}
if f.StreamRecvAvailable(1) != 512 {
t.Fatalf("stream recv=%d, want 512", f.StreamRecvAvailable(1))
}
}

func TestFlowControlReleaseRecvClampsAtLimit(t *testing.T) {
f, _ := NewFlowControl(1024, 1024, 512)
_ = f.OpenStream(1)

// ничего не списывали — Release не должен превысить limit
sessAdded, streamAdded := f.ReleaseRecv(1, 100)
if sessAdded != 0 || streamAdded != 0 {
t.Fatalf("Release at limit should add 0/0, got %d/%d", sessAdded, streamAdded)
}
}

func TestFlowControlClosedStream(t *testing.T) {
f, _ := NewFlowControl(1024, 1024, 512)
_ = f.OpenStream(1)
f.CloseStream(1)

if err := f.ReserveSend(1, 10); err == nil {
t.Fatal("ReserveSend on closed stream should error")
}
if err := f.DeliverRecv(1, 10); err == nil {
t.Fatal("DeliverRecv on closed stream should error")
}
}

func TestFlowControlReservedAccounting(t *testing.T) {
f, _ := NewFlowControl(8192, 8192, 1024)

for i := uint32(1); i <= 5; i++ {
_ = f.OpenStream(i)
}
if f.Reserved() != 5*1024 {
t.Fatalf("Reserved=%d, want %d", f.Reserved(), 5*1024)
}

f.CloseStream(2)
f.CloseStream(4)
if f.Reserved() != 3*1024 {
t.Fatalf("after closes Reserved=%d, want %d", f.Reserved(), 3*1024)
}
}

func TestFlowControlConcurrent(t *testing.T) {
f, _ := NewFlowControl(1<<20, 1<<20, 1<<10)

var wg sync.WaitGroup
for i := uint32(1); i <= 8; i++ {
_ = f.OpenStream(i)
id := i
wg.Add(1)
go func() {
defer wg.Done()
for j := 0; j < 200; j++ {
if err := f.ReserveSend(id, 10); err == nil {
_, _ = f.ReleaseRecv(id, 10)
}
_ = f.SessionSendAvailable()
_ = f.StreamSendAvailable(id)
}
}()
}
wg.Wait()
}

func TestFlowControlErrorTypes(t *testing.T) {
f, _ := NewFlowControl(100, 100, 50)
_ = f.OpenStream(1)

err := f.ReserveSend(1, 200)
var we *ErrorWithCode
if !errors.As(err, &we) {
t.Fatalf("want *ErrorWithCode, got %T", err)
}
if we.Code != CodeFlowControl {
t.Fatalf("code=%v, want CodeFlowControl", we.Code)
}
}
