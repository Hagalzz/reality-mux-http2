package ghostmux

import "sync"

// StreamState — состояние логического потока.
type StreamState uint8

const (
StreamIdle            StreamState = iota // ID выделен, OPEN не отправлен
StreamOpening                            // OPEN отправлен, ждём OPEN_OK/OPEN_ERR
StreamOpened                             // обе стороны могут слать DATA
StreamHalfClosedLocal                    // локальная сторона отправила FIN
StreamHalfClosedRemote                   // удалённая сторона отправила FIN
StreamClosed                             // обе FIN + DATA drained
StreamReset                              // аварийное закрытие
)

func (s StreamState) String() string {
switch s {
case StreamIdle:
return "IDLE"
case StreamOpening:
return "OPENING"
case StreamOpened:
return "OPENED"
case StreamHalfClosedLocal:
return "HALF_CLOSED_LOCAL"
case StreamHalfClosedRemote:
return "HALF_CLOSED_REMOTE"
case StreamClosed:
return "CLOSED"
case StreamReset:
return "RESET"
default:
return "UNKNOWN"
}
}

// Stream — состояние одного логического потока.
//
// Поля сcredit и очереди добавляются в следующих шагах.
// Сейчас — только идентификация и state machine.
type Stream struct {
mu    sync.Mutex
id    uint32
state StreamState
}

// NewStream создаёт поток в состоянии StreamIdle.
// id должен быть ненулевым (0 зарезервирован под session control).
func NewStream(id uint32) (*Stream, error) {
if id == SessionStreamID {
return nil, NewError(CodeProtocolError, "stream_id 0 reserved for session control")
}
return &Stream{id: id, state: StreamIdle}, nil
}

// ID возвращает идентификатор потока.
func (s *Stream) ID() uint32 {
return s.id
}

// State возвращает текущее состояние.
func (s *Stream) State() StreamState {
s.mu.Lock()
defer s.mu.Unlock()
return s.state
}

// Closed возвращает true, если поток в терминальном состоянии.
func (s *Stream) Closed() bool {
st := s.State()
return st == StreamClosed || st == StreamReset
}

// setState — внутренний переход. Вызывающий держит mu.
func (s *Stream) setState(next StreamState) {
s.state = next
}

// Transitions. Все методы возвращают ошибку при недопустимом переходе.

// MarkOpening: IDLE -> OPENING. Локальная сторона отправляет OPEN.
func (s *Stream) MarkOpening() error {
s.mu.Lock()
defer s.mu.Unlock()
if s.state != StreamIdle {
return NewError(CodeProtocolError, "MarkOpening in state %s", s.state)
}
s.setState(StreamOpening)
return nil
}

// MarkOpened: OPENING -> OPENED. Получен OPEN_OK.
func (s *Stream) MarkOpened() error {
s.mu.Lock()
defer s.mu.Unlock()
if s.state != StreamOpening {
return NewError(CodeProtocolError, "MarkOpened in state %s", s.state)
}
s.setState(StreamOpened)
return nil
}

// MarkOpenFailed: OPENING -> RESET. Получен OPEN_ERR или отмена.
func (s *Stream) MarkOpenFailed() error {
s.mu.Lock()
defer s.mu.Unlock()
if s.state != StreamOpening {
return NewError(CodeProtocolError, "MarkOpenFailed in state %s", s.state)
}
s.setState(StreamReset)
return nil
}

// MarkLocalFin: локальная сторона отправляет FIN.
//
// Допустимые переходы:
//   OPENING -> RESET          (отмена до OPEN_OK)
//   OPENED -> HALF_CLOSED_LOCAL
//   HALF_CLOSED_REMOTE -> CLOSED
func (s *Stream) MarkLocalFin() error {
s.mu.Lock()
defer s.mu.Unlock()
switch s.state {
case StreamOpening:
s.setState(StreamReset)
case StreamOpened:
s.setState(StreamHalfClosedLocal)
case StreamHalfClosedRemote:
s.setState(StreamClosed)
default:
return NewError(CodeProtocolError, "MarkLocalFin in state %s", s.state)
}
return nil
}

// MarkRemoteFin: удалённая сторона прислала FIN.
//
// Допустимые переходы:
//   OPENED -> HALF_CLOSED_REMOTE
//   HALF_CLOSED_LOCAL -> CLOSED
func (s *Stream) MarkRemoteFin() error {
s.mu.Lock()
defer s.mu.Unlock()
switch s.state {
case StreamOpened:
s.setState(StreamHalfClosedRemote)
case StreamHalfClosedLocal:
s.setState(StreamClosed)
default:
return NewError(CodeProtocolError, "MarkRemoteFin in state %s", s.state)
}
return nil
}

// MarkReset: аварийное закрытие. Из любого состояния кроме CLOSED/RESET.
func (s *Stream) MarkReset() error {
s.mu.Lock()
defer s.mu.Unlock()
if s.state == StreamClosed || s.state == StreamReset {
return NewError(CodeProtocolError, "MarkReset in state %s", s.state)
}
s.setState(StreamReset)
return nil
}

// CanSendData сообщает, разрешена ли отправка DATA в текущем состоянии.
// DATA разрешена в OPENED и HALF_CLOSED_REMOTE.
func (s *Stream) CanSendData() bool {
st := s.State()
return st == StreamOpened || st == StreamHalfClosedRemote
}

// CanRecvData сообщает, разрешён ли приём DATA в текущем состоянии.
// DATA допустима в OPENED и HALF_CLOSED_LOCAL.
func (s *Stream) CanRecvData() bool {
st := s.State()
return st == StreamOpened || st == StreamHalfClosedLocal
}
