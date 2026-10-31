package ghostmux

import "sync"

// DefaultQuantum — размер кванта DRR для одного потока.
const DefaultQuantum = 32 * 1024

// MaxBatchSize — верхняя граница числа кадров в одном Write.
const MaxBatchSize = 64

// controlQueueID — псевдо-id для control-очереди.
const controlQueueID = ^uint32(0)

// Scheduler — справедливый планировщик очередей кадров.
type Scheduler struct {
	mu      sync.Mutex
	cond    *sync.Cond
	quantum int64

	order   []uint32
	queues  map[uint32]*queue
	control *queue
	cursor  int

	closed bool
}

type queue struct {
	id        uint32
	frames    []*Frame
	deficit   int64
	bytes     int64
	maxBytes  int64
	maxFrames int
}

// NewScheduler создаёт планировщик с заданным квантом.
func NewScheduler(quantum int64) *Scheduler {
	if quantum <= 0 {
		quantum = DefaultQuantum
	}
	s := &Scheduler{
		quantum: quantum,
		queues:  make(map[uint32]*queue),
		control: &queue{id: controlQueueID, maxBytes: 256 * 1024, maxFrames: 256},
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// RegisterStream создаёт очередь для потока.
func (s *Scheduler) RegisterStream(id uint32, maxBytes int64, maxFrames int) error {
	if id == SessionStreamID || id == controlQueueID {
		return NewError(CodeProtocolError, "reserved stream_id for scheduler: %d", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return NewError(CodeProtocolError, "scheduler closed")
	}
	if _, ok := s.queues[id]; ok {
		return NewError(CodeProtocolError, "stream %d already registered", id)
	}
	s.queues[id] = &queue{id: id, maxBytes: maxBytes, maxFrames: maxFrames}
	s.order = append(s.order, id)
	return nil
}

// UnregisterStream удаляет очередь потока.
func (s *Scheduler) UnregisterStream(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.queues[id]; !ok {
		return
	}
	delete(s.queues, id)
	for i, qid := range s.order {
		if qid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			if s.cursor >= len(s.order) {
				s.cursor = 0
			}
			break
		}
	}
}

// EnqueueControl ставит кадр в control-очередь.
func (s *Scheduler) EnqueueControl(f *Frame) error {
	if f == nil {
		return NewError(CodeInternal, "nil frame")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return NewError(CodeProtocolError, "scheduler closed")
	}
	if err := s.control.push(f); err != nil {
		return err
	}
	s.cond.Signal()
	return nil
}

// EnqueueData ставит DATA или FIN-кадр в очередь потока.
func (s *Scheduler) EnqueueData(id uint32, f *Frame) error {
	if f == nil {
		return NewError(CodeInternal, "nil frame")
	}
	// ИСПРАВЛЕНО: Разрешаем FrameFin, чтобы он не обгонял DATA в control-очереди
	if f.Type != FrameData && f.Type != FrameFin {
		return NewError(CodeProtocolError,
			"EnqueueData accepts only FrameData/FrameFin, got 0x%02x", uint8(f.Type))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return NewError(CodeProtocolError, "scheduler closed")
	}
	q, ok := s.queues[id]
	if !ok {
		return NewError(CodeProtocolError, "stream %d not registered", id)
	}
	if err := q.push(f); err != nil {
		return err
	}
	s.cond.Signal()
	return nil
}

func (q *queue) push(f *Frame) error {
	if q.maxFrames > 0 && len(q.frames) >= q.maxFrames {
		return NewError(CodeFlowControl,
			"queue %d full: %d frames", q.id, len(q.frames))
	}
	sz := int64(len(f.Payload))
	if q.maxBytes > 0 && q.bytes+sz > q.maxBytes {
		return NewError(CodeFlowControl,
			"queue %d full: bytes %d+%d > %d", q.id, q.bytes, sz, q.maxBytes)
	}
	q.frames = append(q.frames, f)
	q.bytes += sz
	return nil
}

// nextLocked — общая логика Next/WaitForWork. Вызывающий держит s.mu.
func (s *Scheduler) nextLocked() (*Frame, bool) {
	if s.control != nil && len(s.control.frames) > 0 {
		return s.control.pop(), true
	}
	if len(s.order) == 0 {
		return nil, false
	}
	for attempt := 0; attempt < len(s.order); attempt++ {
		if s.cursor >= len(s.order) {
			s.cursor = 0
		}
		id := s.order[s.cursor]
		q := s.queues[id]
		if q == nil || len(q.frames) == 0 {
			s.cursor++
			continue
		}
		head := q.frames[0]
		sz := int64(len(head.Payload))
		if q.deficit < sz {
			q.deficit += s.quantum
		}
		if q.deficit < sz {
			q.deficit = 0
		}
		f := q.pop()
		q.deficit -= sz
		if q.deficit < 0 {
			q.deficit = 0
		}
		s.cursor++
		return f, true
	}
	return nil, false
}

// Next возвращает следующий кадр или (nil, false).
func (s *Scheduler) Next() (*Frame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextLocked()
}

// WaitForWork блокируется, пока не появится кадр.
func (s *Scheduler) WaitForWork() (*Frame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		f, ok := s.nextLocked()
		if ok {
			return f, true
		}
		if s.closed {
			return nil, false
		}
		s.cond.Wait()
	}
}

// WaitForBatch собирает до max кадров, блокируясь на первом.
func (s *Scheduler) WaitForBatch(max int) ([]*Frame, bool) {
	if max <= 0 {
		max = MaxBatchSize
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		f, ok := s.nextLocked()
		if ok {
			batch := []*Frame{f}
			for len(batch) < max {
				f2, ok2 := s.nextLocked()
				if !ok2 {
					break
				}
				batch = append(batch, f2)
			}
			return batch, true
		}
		if s.closed {
			return nil, false
		}
		s.cond.Wait()
	}
}

func (q *queue) pop() *Frame {
	if len(q.frames) == 0 {
		return nil
	}
	f := q.frames[0]
	q.frames[0] = nil // КРИТИЧЕСКИЙ ФИКС: очищаем ссылку, чтобы GC освободил память
	q.frames = q.frames[1:]
	if len(q.frames) == 0 {
		q.frames = nil
	}
	q.bytes -= int64(len(f.Payload))
	if q.bytes < 0 {
		q.bytes = 0
	}
	return f
}

// Close закрывает планировщик.
func (s *Scheduler) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cond.Broadcast()
}

// Closed сообщает, закрыт ли планировщик.
func (s *Scheduler) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Scheduler) QueuedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, q := range s.queues {
		total += q.bytes
	}
	if s.control != nil {
		total += s.control.bytes
	}
	return total
}

func (s *Scheduler) QueuedFrames() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int
	for _, q := range s.queues {
		total += len(q.frames)
	}
	if s.control != nil {
		total += len(s.control.frames)
	}
	return total
}

func (s *Scheduler) QueueBytes(id uint32) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.queues[id]
	if !ok {
		return -1
	}
	return q.bytes
}

// NextBatch собирает до max кадров без блокировки.
func (s *Scheduler) NextBatch(max int) []*Frame {
	if max <= 0 {
		max = MaxBatchSize
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := make([]*Frame, 0, max)
	for i := 0; i < max; i++ {
		f, ok := s.nextLocked()
		if !ok {
			break
		}
		batch = append(batch, f)
	}
	return batch
}