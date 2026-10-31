package ghostmux

import (
"errors"
"sync"
"testing"
)

func TestSessionStartsIdle(t *testing.T) {
s := NewSession()
if s.State() != SessionIdle {
t.Fatalf("state = %s, want IDLE", s.State())
}
if _, ok := s.RemoteSettings(); ok {
t.Fatal("RemoteSettings should not be set")
}
if s.Flow() != nil {
t.Fatal("Flow should be nil before negotiation")
}
}

func TestSessionHappyPath(t *testing.T) {
s := NewSession()

if err := s.BeginNegotiation(); err != nil {
t.Fatalf("BeginNegotiation: %v", err)
}
if s.State() != SessionNegotiating {
t.Fatalf("state = %s, want NEGOTIATING", s.State())
}

remote := DefaultSettings()
if err := s.AcceptRemoteSettings(remote); err != nil {
t.Fatalf("AcceptRemoteSettings: %v", err)
}
if s.State() != SessionActive {
t.Fatalf("state = %s, want ACTIVE", s.State())
}
if _, ok := s.RemoteSettings(); !ok {
t.Fatal("RemoteSettings should be set")
}
if s.Flow() == nil {
t.Fatal("Flow should be set")
}

if err := s.BeginDraining(); err != nil {
t.Fatalf("BeginDraining: %v", err)
}
if s.State() != SessionDraining {
t.Fatalf("state = %s, want DRAINING", s.State())
}

s.Close()
if s.State() != SessionClosed {
t.Fatalf("state = %s, want CLOSED", s.State())
}
}

func TestSessionBeginDrainingIdempotent(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

if err := s.BeginDraining(); err != nil {
t.Fatal(err)
}
if err := s.BeginDraining(); err != nil {
t.Fatalf("second BeginDraining should be idempotent: %v", err)
}
}

func TestSessionInvalidTransitions(t *testing.T) {
// AcceptRemoteSettings из IDLE
s1 := NewSession()
if err := s1.AcceptRemoteSettings(DefaultSettings()); err == nil {
t.Fatal("AcceptRemoteSettings from IDLE should error")
}

// BeginNegotiation дважды
s2 := NewSession()
_ = s2.BeginNegotiation()
if err := s2.BeginNegotiation(); err == nil {
t.Fatal("double BeginNegotiation should error")
}

// BeginDraining из IDLE
s3 := NewSession()
if err := s3.BeginDraining(); err == nil {
t.Fatal("BeginDraining from IDLE should error")
}
}

func TestSessionZeroWindowRejected(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()

remote := DefaultSettings()
remote.SessionRecvWindow = 0

if err := s.AcceptRemoteSettings(remote); err == nil {
t.Fatal("zero window should be rejected")
}
if s.State() != SessionNegotiating {
t.Fatalf("state should remain NEGOTIATING, got %s", s.State())
}
}

func TestSessionNegotiationUsesMinimum(t *testing.T) {
local := DefaultSettings()
local.SessionRecvWindow = 1 << 20 // 1 MiB
local.StreamRecvWindow = 64 << 10 // 64 KiB
hard := DefaultHardLimits()

s := NewSessionWith(local, hard)
_ = s.BeginNegotiation()

remote := DefaultSettings()
remote.SessionRecvWindow = 512 << 10 // 512 KiB
remote.StreamRecvWindow = 128 << 10  // 128 KiB

if err := s.AcceptRemoteSettings(remote); err != nil {
t.Fatalf("AcceptRemoteSettings: %v", err)
}

// session send должен быть min(512KiB, 1MiB) = 512KiB
if got := s.Flow().SessionSendAvailable(); got != int64(512<<10) {
t.Fatalf("SessionSendAvailable = %d, want %d", got, int64(512<<10))
}
// stream window: min(128KiB, 64KiB) = 64KiB
_ = s.Flow().OpenStream(1)
if got := s.Flow().StreamSendAvailable(1); got != int64(64<<10) {
t.Fatalf("StreamSendAvailable = %d, want %d", got, int64(64<<10))
}
}

func TestSessionNextStreamIDMonotonic(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

ids := []uint32{}
for i := 0; i < 5; i++ {
id, err := s.NextStreamID()
if err != nil {
t.Fatalf("NextStreamID: %v", err)
}
ids = append(ids, id)
}

want := []uint32{1, 3, 5, 7, 9}
for i := range want {
if ids[i] != want[i] {
t.Errorf("ids[%d] = %d, want %d", i, ids[i], want[i])
}
}
}

func TestSessionNextStreamIDBeforeActive(t *testing.T) {
s := NewSession()
if _, err := s.NextStreamID(); err == nil {
t.Fatal("NextStreamID before ACTIVE should error")
}
}

func TestSessionStreamLimit(t *testing.T) {
local := DefaultSettings()
local.MaxStreams = 3
s := NewSessionWith(local, DefaultHardLimits())
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

for i := 0; i < 3; i++ {
if _, err := s.NextStreamID(); err != nil {
t.Fatalf("stream %d: %v", i, err)
}
}
_, err := s.NextStreamID()
if err == nil {
t.Fatal("should hit stream limit")
}
var we *ErrorWithCode
if !errors.As(err, &we) || we.Code != CodeStreamLimit {
t.Fatalf("want CodeStreamLimit, got %v", err)
}
}

func TestSessionDropStream(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

id, _ := s.NextStreamID()
if s.StreamCount() != 1 {
t.Fatalf("StreamCount = %d, want 1", s.StreamCount())
}
if _, ok := s.Stream(id); !ok {
t.Fatal("Stream should exist")
}

s.DropStream(id)
if s.StreamCount() != 0 {
t.Fatalf("StreamCount = %d, want 0", s.StreamCount())
}
if _, ok := s.Stream(id); ok {
t.Fatal("Stream should be gone")
}
if s.Flow().StreamSendAvailable(id) != -1 {
t.Fatal("flow tracker should be closed")
}
}

func TestSessionDropUnownStream(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

s.DropStream(999) // не должно паниковать
if s.StreamCount() != 0 {
t.Fatal("StreamCount should be 0")
}
}

func TestSessionConcurrentStreams(t *testing.T) {
local := DefaultSettings()
local.MaxStreams = 100
s := NewSessionWith(local, DefaultHardLimits())
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

var wg sync.WaitGroup
for i := 0; i < 20; i++ {
wg.Add(1)
go func() {
defer wg.Done()
id, err := s.NextStreamID()
if err != nil {
t.Errorf("NextStreamID: %v", err)
return
}
_, _ = s.Stream(id)
_ = s.StreamCount()
s.DropStream(id)
}()
}
wg.Wait()
}

func TestSessionStateConcurrentReads(t *testing.T) {
s := NewSession()
_ = s.BeginNegotiation()
_ = s.AcceptRemoteSettings(DefaultSettings())

var wg sync.WaitGroup
for i := 0; i < 50; i++ {
wg.Add(1)
go func() {
defer wg.Done()
_ = s.State()
_, _ = s.RemoteSettings()
_ = s.LocalSettings()
_ = s.Flow()
}()
}
wg.Wait()
}
