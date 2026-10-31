# GHOST mux v1 — спецификация протокола

Статус: draft
Дата: 2026-10-12
Область: application-layer мультиплексирование поверх
аутентифицированного REALITY byte-stream.

## 1. Назначение

GHOST mux мультиплексирует несколько логических TCP-потоков
(SOCKS5 CONNECT) в одном физическом соединении.

Ключевые свойства:
- работает поверх ordered byte-stream (net.Conn);
- не знает о TLS/REALITY;
- не делает padding;
- не управляет транспортом;
- не выполняет аутентификацию — доверяет transport layer.

## 2. Границы с REALITY

GHOST mux видит только authenticated REALITY byte-stream.
Fallback-соединения не должны попадать в GHOST parser.

Разделение ответственности:
- REALITY: handshake, аутентификация, маскировка, шифрование.
- GHOST mux: framing, streams, flow control, scheduler.

REALITY adapter обязан различать:
- authenticated application connection -> GHOST session;
- unauthenticated/fallback connection -> существующий camouflage path.

GHOST mux не должен:
- изменять ClientHello;
- вставлять байты до REALITY handshake;
- разбирать TLS records;
- зависеть от границ Read;
- вмешиваться в зеркалирование camouflage target.

## 3. Модель

Клиент открывает логические потоки (streams).
Сервер их принимает и устанавливает outbound TCP.

v1: только клиент открывает потоки (нечётные ID).
Серверные инициативные потоки отложены.

stream_id = 0 зарезервирован для session control.

## 4. Формат кадра

Каждый кадр — фиксированный заголовок 12 байт + payload.

  type        uint8
  flags       uint8
  reserved    uint16
  stream_id   uint32
  length      uint32
  payload     length bytes

Правила:
- byte order: big-endian (network order);
- reserved == 0 для v1 (иначе protocol error);
- допустимые flags зависят от типа кадра;
- length проверяется ДО выделения памяти;
- максимум payload зависит от типа кадра;
- неизвестный обязательный type -> protocol error;
- расширения только после согласования через SETTINGS.

Максимальный payload DATA: 16 KiB.
Это верхняя граница, не обязательный размер.
Кадры НЕ выравниваются до этой границы и не ждут её заполнения.

## 5. Типы кадров

Session control (stream_id = 0):
- SETTINGS       клиент -> сервер, начальные параметры.
- SETTINGS_ACK   сервер -> клиент, подтверждение.
- GOAWAY         graceful shutdown.

Stream control:
- OPEN           клиент -> сервер, открытие потока.
- OPEN_OK        сервер -> клиент, dial успешен.
- OPEN_ERR       сервер -> клиент, dial не удался.
- FIN            half-close направления.
- RESET          аварийное закрытие потока.

Data:
- DATA           прикладные байты.
- WINDOW_UPDATE  пополнение credit.

Keepalive:
- PING / PONG    только при явно включённой опции.

Padding:
- PADDING        зарезервирован, по умолчанию отключён.
                 Отдельная согласованная фича, не часть v1.

## 6. Session negotiation

REALITY handshake/auth completed
    |
    v
client SETTINGS
    |
    v
server SETTINGS_ACK
    |
    v
OPEN permitted

Согласуются:
- версия протокола;
- максимальный размер DATA payload;
- stream receive window;
- connection receive window;
- максимум streams/session;
- поддерживаемые расширения.

Правила:
- peer не может запросить гигабайтные окна или огромные кадры;
- локальные пределы всегда сильнее предложений удалённой стороны;
- DATA до SETTINGS_ACK запрещён;
- отдельный short deadline на negotiation.

## 7. Состояния session

IDLE -> NEGOTIATING -> ACTIVE -> DRAINING -> CLOSED

- IDLE          соединение установлено, SETTINGS не отправлен.
- NEGOTIATING   SETTINGS/SETTINGS_ACK обмен.
- ACTIVE        можно открывать потоки и передавать DATA.
- DRAINING      GOAWAY отправлен, новые OPEN отклоняются.
- CLOSED        все потоки завершены или RESET.

Переход в CLOSED происходит после:
- отправки/приёма GOAWAY и завершения всех streams;
- ошибки парсера (protocol error);
- разрыва transport connection.

## 8. Состояния stream

IDLE -> OPENING -> OPENED -> HALF_CLOSED_LOCAL ->
HALF_CLOSED_REMOTE -> CLOSED

или

IDLE -> OPENING -> OPENED -> RESET

- IDLE                stream_id выделен, OPEN не отправлен.
- OPENING             OPEN отправлен, ждём OPEN_OK/OPEN_ERR.
- OPENED              обе стороны могут слать DATA.
- HALF_CLOSED_LOCAL   локальная сторона отправила FIN.
- HALF_CLOSED_REMOTE  удалённая сторона отправила FIN.
- CLOSED              обе FIN получены + DATA drained.
- RESET               аварийное закрытие, буферы освобождаются.

В OPENING:
- DATA до OPEN_OK запрещён;
- клиент может отправить FIN (отмена);
- повторный OPEN с тем же ID -> protocol error.

## 9. Flow control

Два уровня credit:
- per-stream receive credit;
- per-session receive credit.

Отправка DATA разрешена только в пределах обоих credit.

Стартовые значения (экспериментальные, не оптимальные):
- Максимальный DATA payload    16 KiB
- Stream receive window        128 KiB
- Session receive window       2 MiB
- Максимум streams/session     64
- Aggregate outbound queue     ~2 MiB

Примечание: при RTT 100 ms и goodput ~16 MB/s BDP ~1.6 MB.
Session window 2 MiB близко к BDP — может ограничить bulk.
Значения подлежат уточнению после E0 benchmark.

## 10. Правила credit

- Отправка DATA допускается только при наличии credit
  по обоим уровням.
- Полученный DATA обязан помещаться в память, уже
  зарезервированную выданным credit.
- Если память закончилась при формально допустимом credit —
  это ошибка собственного учёта, а не основание молча терять данные.
- Credit возвращается после потребления из bounded receive buffer,
  не сразу после чтения из REALITY.
- WINDOW_UPDATE отправляется, когда возвращённая часть
  превышает порог (например, половина окна).
- При RESET буферы освобождаются, уже принятые байты учитываются.
  Иначе session credit постепенно утекает.
- Запрещено выдавать credit, не обеспеченный ресурсами.

## 11. Критическое правило reader

Единственный reader общей сессии НИКОГДА не делает
блокирующий Write в destination stream.

Иначе один медленный origin блокирует чтение всех остальных кадров.

Схема обработки входящего DATA:
  session reader
    -> validate frame
    -> debit receive credit
    -> bounded stream queue
    -> stream outbound worker
    -> destination TCP

## 12. Slow stream и session window

Даже с per-stream windows несколько медленных потоков
могут занять весь session window.

Меры:
- ограничение window каждого stream;
- ограничение числа streams;
- общий memory budget на сессию;
- отдельное тестирование blocked-reader workload;
- запрет выдачи credit без ресурсов.

Если несколько stream одновременно пишут в медленные
destination, session window заполняется их данными, и
быстрые stream ждут. Это ожидаемое поведение, его надо
измерять отдельно (scenario: slow reader + short).

## 13. Writer и scheduler

Только ОДИН writer пишет в REALITY connection.
Множество stream queues мультиплексируются в один поток.

  stream queues
    -> deficit round robin
    -> bounded frame batch
    -> single writer
    -> REALITY

- Алгоритм: Deficit Round Robin.
- Quantum: 8-16 KiB (стартовое значение).
- Без искусственной задержки coalescing в v1.
  Разрешено объединять уже готовые кадры в один Write,
  но не ждать специально 1-4 ms.

## 14. Приоритеты control frames

Не все control frames можно безусловно отправлять раньше DATA.

Правила:
- WINDOW_UPDATE может иметь повышенный приоритет —
  иначе peer застрянет без credit.
- RESET отбрасывает очередь соответствующего stream.
- FIN обязан идти ПОСЛЕ всех предшествующих DATA
  этого направления.
- OPEN_OK должен предшествовать ответным DATA
  этого stream.
- SETTINGS/SETTINGS_ACK — вне очереди, до любого DATA.
- Control queue тоже имеет лимиты (bounded).
- GOAWAY отправляется после flush оставшихся кадров
  или с явным указанием причины.

## 15. Порядок кадров (обязательные инварианты)

- SETTINGS -> SETTINGS_ACK -> OPEN -> OPEN_OK -> DATA.
- Нельзя DATA до OPEN_OK.
- Нельзя повторный OPEN с тем же stream_id.
- Нельзя DATA после RESET того же stream.
- Нельзя DATA после FIN в том же направлении.
- FIN идёт после всех предшествующих DATA (в этом направлении).
- WINDOW_UPDATE не может увеличить credit выше согласованного
  максимума.
- stream_id монотонно возрастают, не переиспользуются.
- При исчерпании пространства ID — drain/reconnect.

Нарушение любого инварианта -> protocol error -> RESET stream
или GOAWAY session (в зависимости от тяжести).

## 16. Ошибки

Таблица кодов (черновая):

  OK               0
  PROTOCOL_ERROR   1   неверный заголовок, неизвестный type,
                       нарушение инварианта
  FLOW_CONTROL     2   превышение credit, overflow window
  STREAM_LIMIT     3   превышен максимум streams
  DIAL_FAILED      4   сервер не смог установить outbound
  DIAL_TIMEOUT     5   dial не уложился в deadline
  ADDRESS_DENIED   6   адрес отклонён политикой SSRF
  INTERNAL         7   ошибка реализации
  GOAWAY           8   graceful shutdown

OPEN_ERR payload содержит код + ASCII-описание.
RESET payload содержит код.

Все коды v1 фиксированы. Новые — только через согласование
расширений в SETTINGS.

## 17. Half-close

Семантика:
- SOCKS client EOF
    -> FIN после queued DATA
    -> server outbound CloseWrite()
- origin EOF
    -> FIN после queued DATA
    -> client SOCKS TCP CloseWrite()

Правила:
- Полное освобождение stream — только после завершения
  обоих направлений или RESET.
- После half-close нужен bounded drain timeout:
  противоположная сторона может никогда не закрыться.
- После разрыва общей REALITY-сессии все её streams
  завершаются ошибкой.
- Запрещено автоматически повторять application bytes
  после reconnect: среди них могут быть неидемпотентные операции.
- Повторный FIN -> protocol error.
- DATA после FIN в том же направлении -> protocol error.

## 18. Deadlines

Разделение:
- transport handshake:    общий absolute budget.
- GHOST negotiation:      отдельный короткий budget.
- outbound dial:          свой context на OPEN.
- logical stream deadline: уровень stream.
- session socket deadline: только для общей сессии.

Правило: stream.SetDeadline() НЕ ДОЛЖЕН вызывать
SetDeadline() на общей REALITY connection.
Иначе один поток оборвёт остальные.

После handshake transport deadline необходимо очистить.

## 19. Memory accounting

Каждая сессия имеет общий memory budget.
Он включает:
- bounded stream queues;
- aggregate outbound queue;
- in-flight frame buffers;
- pending OPEN dials (ограниченный пул/semaphore).

Ограничения:
- Session receive window <= memory budget сессии.
- Сумма stream windows <= session window.
- Очередь control frames тоже ограничена.
- Лимиты проверяются до выделения памяти.
- При превышении -> FLOW_CONTROL error, не OOM.

## 20. Что НЕ входит в v1

- UDP ASSOCIATE (SOCKS5).
- SOCKS5 BIND.
- Серверные инициативные потоки.
- Padding.
- Мультисессии / пул REALITY-соединений.
- Автоматический reconnect с replay.
- Multipath / QUIC-подобное восстановление.
- Обфускация длины кадра.
- Шифрование на уровне GHOST (доверяем REALITY).
- Самостоятельная аутентификация внутри GHOST.

## 21. Критерии допуска E0 (correctness)

Обязательные — без них E0 не принимается:
- нет повреждения данных на всех тестах;
- корректный half-close в обе стороны;
- строгие лимиты на все буферы;
- bounded queues (нет неограниченного роста);
- credit accounting без утечек;
- failed stream не ломает session;
- failed session корректно завершает все streams;
- race/fuzz/soak проходят;
- SSRF и auth не регрессируют.

## 22. Критерии производительности E0 (проектные цели)

Для заранее выбранного short workload:
  p95(E0) / p95(A) <= 0.85

Guardrails:
- p99 не хуже A более чем на согласованные 5%;
- bulk goodput не хуже A более чем на 5%;
- отсутствие starvation при bulk+short.

CPU/GiB (если это заявленное преимущество):
  CPU/GiB(E0) / CPU/GiB(A) <= 0.85

"Не хуже на 10%" — промежуточный допуск PoC, не цель.

## 23. Тест-план

Workloads:
- Cold first request      — полная стоимость установления.
- Warm short requests     — эффект mux.
- Persistent H1           — без смешивания handshake.
- Bulk                    — goodput и CPU/GiB.
- Bulk + short            — справедливость scheduler.
- Slow reader + short     — backpressure isolation.
- Slow origin + healthy   — изоляция outbound.
- Connection churn        — OPEN/RESET и ресурсы.
- Idle -> request         — поведение простаивающей сессии.

Concurrency: 1, 4, 8, 16, 32, 64.

Сетка сетевых условий (первая):
  RTT:  0 / 100 / 200 ms
  loss: 0 / 0.5 / 1 %

Jitter, burst loss, reorder — отдельным этапом.

Метрики помимо latency/goodput:
- session establishment time;
- OPEN latency;
- writer queue wait;
- flow-control blocked time;
- per-stream queue occupancy;
- aggregate queued bytes;
- scheduler service gap;
- pending dials;
- DATA/control overhead;
- retransmitted bytes;
- CPU/GiB отдельно client/server;
- FD/RSS/goroutines.

## 24. Unit-тесты (Этап 2, до интеграции с REALITY)

Через net.Pipe и loopback:
- partial reads/writes;
- short writes;
- EOF внутри header;
- EOF внутри payload;
- oversized length;
- WINDOW overflow;
- DATA до OPEN_OK;
- повторный FIN;
- DATA после FIN;
- RESET при активной записи;
- один blocked stream + много healthy;
- shutdown и отмена pending OPEN.

Плюс: decoder/state machine fuzzing, race tests,
goroutine leak tests.

## 25. Открытые вопросы

1. Как REALITY adapter передаёт проверенную user identity
   в GHOST session? Для 8 прод-юзеров это критично.
   Настройки сессии не должны позволять клиенту
   самостоятельно назначить себе пользователя.
   Решение: transport layer передаёт identity как
   часть session context, GHOST её только читает.

2. Нужна ли собственная криптография внутри GHOST?
   Ответ: НЕТ. Доверяем REALITY auth. Если понадобится
   MAC — только через официальный API transport layer.

3. Padding: отдельная фича E1. Исследовать только после
   корректного E0 и только при явной экспериментальной
   опции с ограниченным byte budget.

4. Session window 2 MiB vs BDP 1.6 MB при RTT 100ms.
   Возможно, увеличить до 4 MiB после первых замеров.

5. Scheduler quantum 8-16 KiB — стартовое значение.
   Уточнить по p99 и starvation тестам.

6. Мультисессии (пул REALITY) — отложено на E3+.
   Меняет число handshake и ресурсный профиль.

## 26. Что важно не делать

- Не выравнивать DATA до MSS или фиксированного размера.
- Не писать собственные TLS records.
- Не вводить случайный padding ради красивой гистограммы.
- Не блокировать общий reader на destination I/O.
- Не ставить FIN перед уже принятыми DATA.
- Не применять stream deadlines к общему сокету.
- Не выдавать credit без memory budget.
- Не повторять application traffic после reconnect.
- Не добавлять UDP и multi-session pool в v1.
- Не делать выводы об устойчивости к ТСПУ только из netem.
- Не переносить экспериментальные политики в production
  до отдельного допуска.

## 27. Статус документа

- draft v1, 2026-10-12.
- Следующий шаг: реализация (Этап 2 — mux без REALITY).
- Документ фиксирует интерфейс. Изменения протокола
  требуют обновления этой спецификации до кода.
