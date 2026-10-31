package ghostmux

import "fmt"

// ErrorCode — числовой код ошибки уровня протокола.
// Используется в OPEN_ERR и RESET.
//
// Значения фиксированы для v1. Новые коды — только через
// согласование расширений в SETTINGS.
type ErrorCode uint16

const (
CodeOK            ErrorCode = 0
CodeProtocolError ErrorCode = 1
CodeFlowControl   ErrorCode = 2
CodeStreamLimit   ErrorCode = 3
CodeDialFailed    ErrorCode = 4
CodeDialTimeout   ErrorCode = 5
CodeAddressDenied ErrorCode = 6
CodeInternal      ErrorCode = 7
CodeGoAway        ErrorCode = 8
)

// String возвращает человекочитаемое имя кода.
func (c ErrorCode) String() string {
switch c {
case CodeOK:
return "OK"
case CodeProtocolError:
return "PROTOCOL_ERROR"
case CodeFlowControl:
return "FLOW_CONTROL"
case CodeStreamLimit:
return "STREAM_LIMIT"
case CodeDialFailed:
return "DIAL_FAILED"
case CodeDialTimeout:
return "DIAL_TIMEOUT"
case CodeAddressDenied:
return "ADDRESS_DENIED"
case CodeInternal:
return "INTERNAL"
case CodeGoAway:
return "GOAWAY"
default:
return fmt.Sprintf("UNKNOWN(%d)", uint16(c))
}
}

// Known сообщает, зарегистрирован ли код в v1.
func (c ErrorCode) Known() bool {
return c >= CodeOK && c <= CodeGoAway
}

// ErrorWithCode — ошибка с числовым кодом и ASCII-описанием.
// Используется как payload для OPEN_ERR и RESET.
type ErrorWithCode struct {
Code ErrorCode
Msg  string
}

func (e *ErrorWithCode) Error() string {
if e.Msg == "" {
return e.Code.String()
}
return fmt.Sprintf("%s: %s", e.Code.String(), e.Msg)
}

// NewError создаёт ошибку с кодом.
func NewError(code ErrorCode, format string, args ...any) *ErrorWithCode {
return &ErrorWithCode{
Code: code,
Msg:  fmt.Sprintf(format, args...),
}
}
