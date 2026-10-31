package ghostmux

import "sync"

// SessionState — состояние GHOST-сессии.
type SessionState uint8

const (
SessionIdle         SessionState = iota // соединение установлено, SETTINGS не отправлен
SessionNegotiating                      // SETTINGS/SETTINGS_ACK обмен
SessionActive                           // можно открывать потоки и слать DATA
SessionDraining                         // GOAWAY отправлен, новые OPEN отклоняются
SessionClosed                           // все потоки завершены
)

func (s SessionState) String() string {
switch s {
case SessionIdle:
return "IDLE"
case SessionNegotiating:
return "NEGOTIATING"
case SessionActive:
return "ACTIVE"
case SessionDraining:
return "DRAINING"
case SessionClosed:
return "CLOSED"
default:
return "UNKNOWN"
}
}

// Session — состояние одной GHOST-сессии поверх REALITY byte-stream.
//
// Не владеет net.Conn. I/O добавляется в следующих этапах.
// Сейчас — только состояние, потоки, инварианты.
type Session struct {
mu    sync.Mutex
state SessionState

// Согласованные параметры.
local  Settings
remote *Settings // nil до SETTINGS_ACK

hard HardLimits

// Потоки. id -> *Stream.
streams map[uint32]*Stream

// lastStreamID — последний выделенный id.
// v1: только клиент открывает, id монотонно возрастают.
lastStreamID uint32

// flow — двухуровневый control. Создаётся при активации.
flow *FlowControl
}

// NewSession создаёт сессию в состоянии SessionIdle с локальными
// настройками по умолчанию.
func NewSession() *Session {
return &Session{
state:  SessionIdle,
local:  DefaultSettings(),
hard:   DefaultHardLimits(),
streams: make(map[uint32]*Stream),
}
}

// NewSessionWith создаёт сессию с явными настройками и hard limits.
// Полезно для тестов.
func NewSessionWith(local Settings, hard HardLimits) *Session {
return &Session{
state:  SessionIdle,
local:  local,
hard:   hard,
streams: make(map[uint32]*Stream),
}
}

// State возвращает текущее состояние сессии.
func (s *Session) State() SessionState {
s.mu.Lock()
defer s.mu.Unlock()
return s.state
}

// LocalSettings возвращает локальные настройки (копию).
func (s *Session) LocalSettings() Settings {
s.mu.Lock()
defer s.mu.Unlock()
return s.local
}

// RemoteSettings возвращает согласованные параметры peer.
// Возвращает (Settings{}, false), если SETTINGS_ACK ещё не получен.
func (s *Session) RemoteSettings() (Settings, bool) {
s.mu.Lock()
defer s.mu.Unlock()
if s.remote == nil {
return Settings{}, false
}
return *s.remote, true
}

// BeginNegotiation: IDLE -> NEGOTIATING.
func (s *Session) BeginNegotiation() error {
s.mu.Lock()
defer s.mu.Unlock()
if s.state != SessionIdle {
return NewError(CodeProtocolError, "BeginNegotiation in state %s", s.state)
}
s.state = SessionNegotiating
return nil
}

// AcceptRemoteSettings: NEGOTIATING -> ACTIVE.
//
// Валидирует SETTINGS peer'а против hard limits и создаёт
// FlowControl с согласованными окнами.
//
// Локальные пределы всегда сильнее: если peer предложил больше,
// DecodeSettings уже отклонит это.
func (s *Session) AcceptRemoteSettings(remote Settings) error {
s.mu.Lock()
defer s.mu.Unlock()

if s.state != SessionNegotiating {
return NewError(CodeProtocolError, "AcceptRemoteSettings in state %s", s.state)
}

// Выбираем минимумы: то, что готовы отдать мы, и то, что
// готов принять peer.
sessSend := int64(minU32(remote.SessionRecvWindow, s.local.SessionRecvWindow))
sessRecv := int64(s.local.SessionRecvWindow)
streamMax := int64(minU32(remote.StreamRecvWindow, s.local.StreamRecvWindow))

if sessSend <= 0 || sessRecv <= 0 || streamMax <= 0 {
return NewError(CodeProtocolError, "zero window after negotiation")
}

flow, err := NewFlowControl(sessSend, sessRecv, streamMax)
if err != nil {
return err
}

cp := remote
s.remote = &cp
s.flow = flow
s.state = SessionActive
return nil
}

// BeginDraining: ACTIVE -> DRAINING. Новые OPEN отклоняются.
func (s *Session) BeginDraining() error {
s.mu.Lock()
defer s.mu.Unlock()
switch s.state {
case SessionActive:
s.state = SessionDraining
return nil
case SessionDraining:
return nil // идемпотентно
default:
return NewError(CodeProtocolError, "BeginDraining in state %s", s.state)
}
}

// Close: -> CLOSED. Идемпотентно.
func (s *Session) Close() {
s.mu.Lock()
defer s.mu.Unlock()
s.state = SessionClosed
}

// NextStreamID выделяет следующий нечётный id (v1: клиентская сторона).
//
// Возвращает ошибку, если:
//   - сессия не ACTIVE;
//   - достигнут MaxStreams;
//   - исчерпано пространство id.
func (s *Session) NextStreamID() (uint32, error) {
s.mu.Lock()
defer s.mu.Unlock()

if s.state != SessionActive {
return 0, NewError(CodeProtocolError, "NextStreamID in state %s", s.state)
}
if uint32(len(s.streams)) >= s.local.MaxStreams {
return 0, NewError(CodeStreamLimit,
"max streams reached: %d", s.local.MaxStreams)
}
if s.lastStreamID > 0xFFFFFFFE {
return 0, NewError(CodeStreamLimit, "stream_id space exhausted")
}

// Первый id = 1, далее +2 (только нечётные для клиента v1).
var next uint32
if s.lastStreamID == 0 {
next = 1
} else {
next = s.lastStreamID + 2
if next == 0 || next <= s.lastStreamID {
return 0, NewError(CodeStreamLimit, "stream_id overflow")
}
}

st, err := NewStream(next)
if err != nil {
return 0, err
}
if err := st.MarkOpening(); err != nil {
return 0, err
}
s.streams[next] = st
s.lastStreamID = next

if s.flow != nil {
if err := s.flow.OpenStream(next); err != nil {
delete(s.streams, next)
return 0, err
}
}
return next, nil
}

// Stream возвращает поток по id.
func (s *Session) Stream(id uint32) (*Stream, bool) {
s.mu.Lock()
defer s.mu.Unlock()
st, ok := s.streams[id]
return st, ok
}

// StreamCount возвращает число активных потоков.
func (s *Session) StreamCount() int {
s.mu.Lock()
defer s.mu.Unlock()
return len(s.streams)
}

// DropStream удаляет поток из таблицы. Вызывается после CLOSED/RESET.
func (s *Session) DropStream(id uint32) {
s.mu.Lock()
flow := s.flow
delete(s.streams, id)
s.mu.Unlock()

if flow != nil {
flow.CloseStream(id)
}
}

// Flow возвращает FlowControl. nil до AcceptRemoteSettings.
func (s *Session) Flow() *FlowControl {
s.mu.Lock()
defer s.mu.Unlock()
return s.flow
}

// minU32 — минимум двух uint32.
func minU32(a, b uint32) uint32 {
if a < b {
return a
}
return b
}
