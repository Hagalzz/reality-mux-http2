package ghostmux

import (
	"errors"
	"sync"
	"testing"
)

func mkFrame(typ FrameType, sid uint32, payload int) *Frame {
	return &Frame{Type: typ, StreamID: sid, Payload: make([]byte, payload)}
}

func TestSchedulerRegisterUnregister(t *testing.T) {
	s := NewScheduler(0)

	if err := s.RegisterStream(SessionStreamID, 0, 0); err == nil {
		t.Fatal("stream_id 0 should be rejected")
	}
	if err := s.RegisterStream(controlQueueID, 0, 0); err == nil {
		t.Fatal("control id should be rejected")
	}
	if err := s.RegisterStream(1, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterStream(1, 0, 0); err == nil {
		t.Fatal("double register should error")
	}

	s.UnregisterStream(1)
	if s.QueuedFrames() != 0 {
		t.Fatal("queue should be empty after unregister")
	}
}

func TestSchedulerControlPriority(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 0, 0)

	_ = s.EnqueueData(1, mkFrame(FrameData, 1, 100))
	_ = s.EnqueueControl(mkFrame(FrameOpenOK, 0, 0))
	_ = s.EnqueueData(1, mkFrame(FrameData, 1, 100))

	f, ok := s.Next()
	if !ok {
		t.Fatal("Next should return a frame")
	}
	if f.Type != FrameOpenOK {
		t.Fatalf("control priority broken: got %v, want OPEN_OK", f.Type)
	}
}

func TestSchedulerRoundRobinFairness(t *testing.T) {
	s := NewScheduler(100)
	_ = s.RegisterStream(1, 0, 0)
	_ = s.RegisterStream(3, 0, 0)
	_ = s.RegisterStream(5, 0, 0)

	// по 3 кадра в каждой очереди, одинакового размера
	for i := 0; i < 3; i++ {
		_ = s.EnqueueData(1, mkFrame(FrameData, 1, 50))
		_ = s.EnqueueData(3, mkFrame(FrameData, 3, 50))
		_ = s.EnqueueData(5, mkFrame(FrameData, 5, 50))
	}

	// Первые три кадра должны быть из разных очередей.
	seen := map[uint32]int{}
	for i := 0; i < 3; i++ {
		f, _ := s.Next()
		seen[f.StreamID]++
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct streams in first 3 frames, got %v", seen)
	}
}

func TestSchedulerQuantumDeficit(t *testing.T) {
	s := NewScheduler(200)
	_ = s.RegisterStream(1, 0, 0)
	_ = s.RegisterStream(3, 0, 0)

	// Кадры по 150 байт: quantum 200 покрывает только один за раз.
	for i := 0; i < 2; i++ {
		_ = s.EnqueueData(1, mkFrame(FrameData, 1, 150))
		_ = s.EnqueueData(3, mkFrame(FrameData, 3, 150))
	}

	// Первые два Next должны попасть в разные очереди.
	f1, _ := s.Next()
	f2, _ := s.Next()
	if f1.StreamID == f2.StreamID {
		t.Fatalf("quantum should rotate streams: both from %d", f1.StreamID)
	}
}

func TestSchedulerOversizedFrameStillSends(t *testing.T) {
	s := NewScheduler(100)
	_ = s.RegisterStream(1, 0, 0)

	// кадр больше quantum
	_ = s.EnqueueData(1, mkFrame(FrameData, 1, 500))

	f, ok := s.Next()
	if !ok || f == nil {
		t.Fatal("oversized frame should still be sent")
	}
}

func TestSchedulerQueueLimits(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 500, 3)

	if err := s.EnqueueData(1, mkFrame(FrameData, 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueData(1, mkFrame(FrameData, 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueData(1, mkFrame(FrameData, 1, 100)); err != nil {
		t.Fatal(err)
	}
	// 4-й должен упасть по maxFrames
	err := s.EnqueueData(1, mkFrame(FrameData, 1, 100))
	if err == nil {
		t.Fatal("should hit maxFrames limit")
	}
	var we *ErrorWithCode
	if !errors.As(err, &we) || we.Code != CodeFlowControl {
		t.Fatalf("want CodeFlowControl, got %v", err)
	}
}

func TestSchedulerQueueBytesLimit(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 300, 0)

	if err := s.EnqueueData(1, mkFrame(FrameData, 1, 200)); err != nil {
		t.Fatal(err)
	}
	// 200 + 200 = 400 > 300
	err := s.EnqueueData(1, mkFrame(FrameData, 1, 200))
	if err == nil {
		t.Fatal("should hit maxBytes limit")
	}
}

func TestSchedulerRejectsWrongType(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 0, 0)

	err := s.EnqueueData(1, mkFrame(FrameReset, 1, 0))
	if err == nil {
		t.Fatal("EnqueueData should reject non-DATA/FIN frame")
	}
}

func TestSchedulerUnregisteredStream(t *testing.T) {
	s := NewScheduler(0)

	err := s.EnqueueData(99, mkFrame(FrameData, 99, 10))
	if err == nil {
		t.Fatal("EnqueueData for unregistered stream should error")
	}
}

func TestSchedulerEmpty(t *testing.T) {
	s := NewScheduler(0)
	f, ok := s.Next()
	if ok || f != nil {
		t.Fatalf("empty scheduler should return (nil,false), got (%v,%v)", f, ok)
	}
}

func TestSchedulerQueuedBytes(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 0, 0)
	_ = s.RegisterStream(3, 0, 0)

	_ = s.EnqueueData(1, mkFrame(FrameData, 1, 100))
	_ = s.EnqueueData(1, mkFrame(FrameData, 1, 50))
	_ = s.EnqueueData(3, mkFrame(FrameData, 3, 200))
	_ = s.EnqueueControl(mkFrame(FramePing, 0, 0))

	if s.QueuedFrames() != 4 {
		t.Fatalf("QueuedFrames = %d, want 4", s.QueuedFrames())
	}
	if s.QueuedBytes() != 350 {
		t.Fatalf("QueuedBytes = %d, want 350", s.QueuedBytes())
	}
	if s.QueueBytes(1) != 150 {
		t.Fatalf("QueueBytes(1) = %d, want 150", s.QueueBytes(1))
	}
	if s.QueueBytes(99) != -1 {
		t.Fatalf("QueueBytes(99) = %d, want -1", s.QueueBytes(99))
	}
}

func TestSchedulerNextBatch(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 0, 0)

	for i := 0; i < 10; i++ {
		_ = s.EnqueueData(1, mkFrame(FrameData, 1, 10))
	}

	batch := s.NextBatch(3)
	if len(batch) != 3 {
		t.Fatalf("batch len = %d, want 3", len(batch))
	}
	if s.QueuedFrames() != 7 {
		t.Fatalf("queued = %d, want 7", s.QueuedFrames())
	}
}

func TestSchedulerClose(t *testing.T) {
	s := NewScheduler(0)
	_ = s.RegisterStream(1, 0, 0)
	s.Close()

	if err := s.RegisterStream(3, 0, 0); err == nil {
		t.Fatal("RegisterStream after Close should error")
	}
	if err := s.EnqueueData(1, mkFrame(FrameData, 1, 10)); err == nil {
		t.Fatal("EnqueueData after Close should error")
	}
	if err := s.EnqueueControl(mkFrame(FramePing, 0, 0)); err == nil {
		t.Fatal("EnqueueControl after Close should error")
	}
}

func TestSchedulerConcurrent(t *testing.T) {
	s := NewScheduler(1024)
	for i := uint32(1); i <= 8; i++ {
		_ = s.RegisterStream(i, 0, 0)
	}

	var wg sync.WaitGroup
	for i := uint32(1); i <= 8; i++ {
		id := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = s.EnqueueData(id, mkFrame(FrameData, id, 20))
				_, _ = s.Next()
			}
		}()
	}

	// параллельный reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 300; j++ {
			_, _ = s.Next()
			_ = s.QueuedBytes()
		}
	}()
	wg.Wait()
}
