package ghostmux

import (
"errors"
"sync"
"testing"
)

func TestNewStreamRejectsSessionID(t *testing.T) {
_, err := NewStream(SessionStreamID)
if err == nil {
t.Fatal("want error for stream_id 0, got nil")
}
}

func TestNewStreamStartsIdle(t *testing.T) {
s, err := NewStream(1)
if err != nil {
t.Fatalf("NewStream: %v", err)
}
if s.State() != StreamIdle {
t.Fatalf("initial state = %s, want IDLE", s.State())
}
if s.Closed() {
t.Fatal("fresh stream should not be closed")
}
}

func TestHappyPathOpenAndClose(t *testing.T) {
s, _ := NewStream(3)

if err := s.MarkOpening(); err != nil {
t.Fatalf("MarkOpening: %v", err)
}
if err := s.MarkOpened(); err != nil {
t.Fatalf("MarkOpened: %v", err)
}
if !s.CanSendData() || !s.CanRecvData() {
t.Fatal("OPENED should allow both directions")
}

if err := s.MarkLocalFin(); err != nil {
t.Fatalf("MarkLocalFin: %v", err)
}
if s.State() != StreamHalfClosedLocal {
t.Fatalf("state = %s, want HALF_CLOSED_LOCAL", s.State())
}
if s.CanSendData() {
t.Fatal("HALF_CLOSED_LOCAL should not allow send")
}
if !s.CanRecvData() {
t.Fatal("HALF_CLOSED_LOCAL should allow recv")
}

if err := s.MarkRemoteFin(); err != nil {
t.Fatalf("MarkRemoteFin: %v", err)
}
if s.State() != StreamClosed {
t.Fatalf("state = %s, want CLOSED", s.State())
}
if !s.Closed() {
t.Fatal("CLOSED should report Closed() = true")
}
}

func TestReverseHalfClose(t *testing.T) {
s, _ := NewStream(5)
_ = s.MarkOpening()
_ = s.MarkOpened()

if err := s.MarkRemoteFin(); err != nil {
t.Fatalf("MarkRemoteFin: %v", err)
}
if s.State() != StreamHalfClosedRemote {
t.Fatalf("state = %s, want HALF_CLOSED_REMOTE", s.State())
}
if !s.CanSendData() {
t.Fatal("HALF_CLOSED_REMOTE should allow send")
}
if s.CanRecvData() {
t.Fatal("HALF_CLOSED_REMOTE should not allow recv")
}

if err := s.MarkLocalFin(); err != nil {
t.Fatalf("MarkLocalFin: %v", err)
}
if s.State() != StreamClosed {
t.Fatalf("state = %s, want CLOSED", s.State())
}
}

func TestCancelDuringOpening(t *testing.T) {
s, _ := NewStream(7)
_ = s.MarkOpening()

if err := s.MarkLocalFin(); err != nil {
t.Fatalf("MarkLocalFin during OPENING: %v", err)
}
if s.State() != StreamReset {
t.Fatalf("state = %s, want RESET", s.State())
}
if !s.Closed() {
t.Fatal("RESET should report Closed() = true")
}
}

func TestOpenFailedDuringOpening(t *testing.T) {
s, _ := NewStream(9)
_ = s.MarkOpening()

if err := s.MarkOpenFailed(); err != nil {
t.Fatalf("MarkOpenFailed: %v", err)
}
if s.State() != StreamReset {
t.Fatalf("state = %s, want RESET", s.State())
}
}

func TestResetFromAnyState(t *testing.T) {
states := []struct {
name string
set  func(*Stream)
}{
{"IDLE", func(s *Stream) {}},
{"OPENING", func(s *Stream) { _ = s.MarkOpening() }},
{"OPENED", func(s *Stream) { _ = s.MarkOpening(); _ = s.MarkOpened() }},
{"HALF_CLOSED_LOCAL", func(s *Stream) {
_ = s.MarkOpening()
_ = s.MarkOpened()
_ = s.MarkLocalFin()
}},
{"HALF_CLOSED_REMOTE", func(s *Stream) {
_ = s.MarkOpening()
_ = s.MarkOpened()
_ = s.MarkRemoteFin()
}},
}
for i, c := range states {
s, _ := NewStream(uint32(11 + i*2))
c.set(s)
if err := s.MarkReset(); err != nil {
t.Errorf("%s: MarkReset: %v", c.name, err)
}
if s.State() != StreamReset {
t.Errorf("%s: state = %s, want RESET", c.name, s.State())
}
}
}

func TestInvalidTransitions(t *testing.T) {
cases := []struct {
name string
set  func(*Stream)
fn   func(*Stream) error
}{
{"MarkOpened_from_IDLE", func(s *Stream) {}, (*Stream).MarkOpened},
{"MarkOpened_from_OPENED", func(s *Stream) {
_ = s.MarkOpening()
_ = s.MarkOpened()
}, (*Stream).MarkOpened},
{"MarkOpening_twice", func(s *Stream) { _ = s.MarkOpening() }, (*Stream).MarkOpening},
{"MarkLocalFin_from_IDLE", func(s *Stream) {}, (*Stream).MarkLocalFin},
{"MarkRemoteFin_from_IDLE", func(s *Stream) {}, (*Stream).MarkRemoteFin},
{"MarkRemoteFin_from_OPENING", func(s *Stream) { _ = s.MarkOpening() }, (*Stream).MarkRemoteFin},
}
for i, c := range cases {
s, _ := NewStream(uint32(101 + i*2))
c.set(s)
err := c.fn(s)
if err == nil {
t.Errorf("%s: want error, got nil", c.name)
continue
}
var we *ErrorWithCode
if !errors.As(err, &we) {
t.Errorf("%s: error is not *ErrorWithCode: %v", c.name, err)
}
}
}

func TestMarkResetAfterClosed(t *testing.T) {
s, _ := NewStream(51)
_ = s.MarkOpening()
_ = s.MarkOpened()
_ = s.MarkLocalFin()
_ = s.MarkRemoteFin()

if err := s.MarkReset(); err == nil {
t.Fatal("MarkReset after CLOSED should error")
}
}

func TestStreamConcurrentStateReads(t *testing.T) {
s, _ := NewStream(61)
_ = s.MarkOpening()
_ = s.MarkOpened()

var wg sync.WaitGroup
for i := 0; i < 50; i++ {
wg.Add(1)
go func() {
defer wg.Done()
_ = s.State()
_ = s.Closed()
_ = s.CanSendData()
_ = s.CanRecvData()
}()
}
wg.Wait()
}
