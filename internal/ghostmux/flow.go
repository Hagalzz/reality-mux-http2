package ghostmux

import "sync"

// CreditTracker — счётчик credit в одном направлении.
//
// Семантика:
//   avail — сколько байт разрешено к передаче/приёму прямо сейчас.
//   limit — согласованный максимум. avail никогда не превышает limit.
//
// Все методы потокобезопасны.
type CreditTracker struct {
mu    sync.Mutex
avail int64
limit int64
}

// NewCreditTracker создаёт трекер с заданным начальным и максимальным credit.
// Оба должны быть >= 0, avail <= limit.
func NewCreditTracker(initial, limit int64) (*CreditTracker, error) {
if initial < 0 || limit < 0 || initial > limit {
return nil, NewError(CodeInternal,
"invalid credit init: initial=%d limit=%d", initial, limit)
}
return &CreditTracker{avail: initial, limit: limit}, nil
}

// Available возвращает текущий доступный credit.
func (c *CreditTracker) Available() int64 {
c.mu.Lock()
defer c.mu.Unlock()
return c.avail
}

// Limit возвращает согласованный максимум.
func (c *CreditTracker) Limit() int64 {
c.mu.Lock()
defer c.mu.Unlock()
return c.limit
}

// Consume списывает n байт credit.
//
// Возвращает ErrFlowControl, если n > avail. В этом случае
// состояние не меняется.
//
// n == 0 — no-op, возвращает nil.
func (c *CreditTracker) Consume(n int64) error {
if n < 0 {
return NewError(CodeInternal, "Consume negative: %d", n)
}
if n == 0 {
return nil
}
c.mu.Lock()
defer c.mu.Unlock()
if n > c.avail {
return NewError(CodeFlowControl,
"credit exhausted: need=%d avail=%d", n, c.avail)
}
c.avail -= n
return nil
}

// Grant увеличивает credit на n байт (WINDOW_UPDATE).
//
// Возвращает фактически добавленное количество. Если сумма
// превышает limit — credit обрезается до limit, лишнее не добавляется.
// Это защита от злонамеренного peer.
//
// Возвращает ErrFlowControl, если n < 0.
func (c *CreditTracker) Grant(n int64) (int64, error) {
if n < 0 {
return 0, NewError(CodeFlowControl, "Grant negative: %d", n)
}
if n == 0 {
return 0, nil
}
c.mu.Lock()
defer c.mu.Unlock()
headroom := c.limit - c.avail
if headroom <= 0 {
return 0, nil
}
added := n
if added > headroom {
added = headroom
}
c.avail += added
return added, nil
}

// FlowControl — двухуровневый контроль потока для одной сессии.
//
// Каждый stream имеет свою пару send/recv credit. Сессия имеет
// свою пару. DATA считается разрешённой, только если credit
// есть на ОБОИХ уровнях.
//
// Роли:
//   send — то, что нам разрешил peer отправлять (мы ограничены).
//   recv — то, что мы разрешили peer'у отправлять (мы выдаём).
type FlowControl struct {
mu sync.Mutex

sessionSend *CreditTracker
sessionRecv *CreditTracker

// per-stream: ключ — stream_id.
streamSend map[uint32]*CreditTracker
streamRecv map[uint32]*CreditTracker

// hard limits и defaults для новых stream.
streamWindowMax int64
defaultStream   int64

// memory accounting: сколько байт уже "зарезервировано"
// под recv credit. Не превышает sessionRecv.Limit.
reserved int64
}

// NewFlowControl создаёт двухуровневый трекер.
//
// sessionSendInit, sessionRecvInit — начальные окна сессии.
// streamWindowMax — верхняя граница per-stream окна.
// Возвращает ошибку при некорректных параметрах.
func NewFlowControl(sessionSendInit, sessionRecvInit, streamWindowMax int64) (*FlowControl, error) {
if streamWindowMax <= 0 {
return nil, NewError(CodeInternal, "streamWindowMax must be > 0")
}
ss, err := NewCreditTracker(sessionSendInit, sessionSendInit)
if err != nil {
return nil, err
}
sr, err := NewCreditTracker(sessionRecvInit, sessionRecvInit)
if err != nil {
return nil, err
}
return &FlowControl{
sessionSend:     ss,
sessionRecv:     sr,
streamSend:      make(map[uint32]*CreditTracker),
streamRecv:      make(map[uint32]*CreditTracker),
streamWindowMax: streamWindowMax,
defaultStream:   streamWindowMax,
}, nil
}

// OpenStream регистрирует пару трекеров для нового потока.
// Возвращает ошибку, если stream уже открыт или id == 0.
func (f *FlowControl) OpenStream(id uint32) error {
if id == SessionStreamID {
return NewError(CodeProtocolError, "stream_id 0 reserved")
}
f.mu.Lock()
defer f.mu.Unlock()
if _, ok := f.streamSend[id]; ok {
return NewError(CodeProtocolError, "stream %d already open", id)
}

// send credit = сколько peer готов принять от нас.
// Стартовое значение = defaultStream (это наше предположение,
// уточняется SETTINGS peer'а до первого DATA).
send, err := NewCreditTracker(f.defaultStream, f.defaultStream)
if err != nil {
return err
}
// recv credit = сколько мы готовы принять от peer.
// Ограничен streamWindowMax.
recv, err := NewCreditTracker(f.defaultStream, f.streamWindowMax)
if err != nil {
return err
}
f.streamSend[id] = send
f.streamRecv[id] = recv
f.reserved += f.defaultStream
return nil
}

// CloseStream освобождает трекеры потока.
//
// Не возвращает уже использованный credit в session: он
// списывается по мере потребления. Просто удаляет per-stream записи.
func (f *FlowControl) CloseStream(id uint32) {
f.mu.Lock()
defer f.mu.Unlock()
if recv, ok := f.streamRecv[id]; ok {
f.reserved -= recv.Limit()
if f.reserved < 0 {
f.reserved = 0
}
}
delete(f.streamSend, id)
delete(f.streamRecv, id)
}

// CanSendData проверяет, разрешена ли отправка n байт DATA
// на уровне обоих credit. Не списывает credit — только проверяет.
//
// Возвращает ErrFlowControl, если credit недостаточно.
func (f *FlowControl) CanSendData(id uint32, n int64) error {
if n < 0 {
return NewError(CodeInternal, "CanSendData negative: %d", n)
}
if n == 0 {
return nil
}
f.mu.Lock()
ss, sr := f.sessionSend, f.streamSend[id]
f.mu.Unlock()

if sr == nil {
return NewError(CodeProtocolError, "stream %d not open", id)
}
if ss.Available() < n {
return NewError(CodeFlowControl,
"session send credit: need=%d avail=%d", n, ss.Available())
}
if sr.Available() < n {
return NewError(CodeFlowControl,
"stream %d send credit: need=%d avail=%d", id, n, sr.Available())
}
return nil
}

// ReserveSend списывает n байт send credit на обоих уровнях.
// Вызывается ровно перед отправкой DATA.
//
// При неудаче на втором уровне откатывает первый (rollback),
// чтобы состояние оставалось согласованным.
func (f *FlowControl) ReserveSend(id uint32, n int64) error {
if n < 0 {
return NewError(CodeInternal, "ReserveSend negative: %d", n)
}
if n == 0 {
return nil
}
f.mu.Lock()
ss, sr := f.sessionSend, f.streamSend[id]
f.mu.Unlock()

if sr == nil {
return NewError(CodeProtocolError, "stream %d not open", id)
}
if err := ss.Consume(n); err != nil {
return err
}
if err := sr.Consume(n); err != nil {
// rollback session — иначе credit утечёт
_, _ = ss.Grant(n)
return err
}
return nil
}

// DeliverRecv вызывается при получении DATA от peer.
// Проверяет, что оба recv credit позволяют принять n байт,
// и списывает их.
//
// Это не «возврат credit после потребления» — это списание
// выданного нами разрешения. Возврат делается через ReleaseRecv.
func (f *FlowControl) DeliverRecv(id uint32, n int64) error {
if n < 0 {
return NewError(CodeInternal, "DeliverRecv negative: %d", n)
}
if n == 0 {
return nil
}
f.mu.Lock()
sr, rr := f.sessionRecv, f.streamRecv[id]
f.mu.Unlock()

if rr == nil {
return NewError(CodeProtocolError, "stream %d not open", id)
}
if err := sr.Consume(n); err != nil {
return err
}
if err := rr.Consume(n); err != nil {
_, _ = sr.Grant(n)
return err
}
return nil
}

// ReleaseRecv возвращает n байт recv credit на обоих уровнях
// после того, как данные были потреблены из bounded buffer.
//
// Именно после ПОТРЕБЛЕНИЯ, не после чтения из REALITY —
// иначе снимается backpressure.
func (f *FlowControl) ReleaseRecv(id uint32, n int64) (sessionAdded, streamAdded int64) {
if n <= 0 {
return 0, 0
}
f.mu.Lock()
sr, rr := f.sessionRecv, f.streamRecv[id]
f.mu.Unlock()

if sr != nil {
sessionAdded, _ = sr.Grant(n)
}
if rr != nil {
streamAdded, _ = rr.Grant(n)
}
return sessionAdded, streamAdded
}

// SessionSendAvailable — для диагностики и тестов.
func (f *FlowControl) SessionSendAvailable() int64 {
return f.sessionSend.Available()
}

// SessionRecvAvailable — для диагностики и тестов.
func (f *FlowControl) SessionRecvAvailable() int64 {
return f.sessionRecv.Available()
}

// StreamSendAvailable — для диагностики и тестов.
func (f *FlowControl) StreamSendAvailable(id uint32) int64 {
f.mu.Lock()
t := f.streamSend[id]
f.mu.Unlock()
if t == nil {
return -1
}
return t.Available()
}

// StreamRecvAvailable — для диагностики и тестов.
func (f *FlowControl) StreamRecvAvailable(id uint32) int64 {
f.mu.Lock()
t := f.streamRecv[id]
f.mu.Unlock()
if t == nil {
return -1
}
return t.Available()
}

// Reserved — суммарный recv credit, выданный всем открытым streams.
// Используется для memory accounting. Не превышает session recv limit.
func (f *FlowControl) Reserved() int64 {
f.mu.Lock()
defer f.mu.Unlock()
return f.reserved
}
