// Package ghostmux реализует application-layer мультиплексирование
// поверх аутентифицированного REALITY byte-stream.
//
// Спецификация: internal/ghostmux/PROTOCOL.md
package ghostmux

import (
"encoding/binary"
"errors"
"fmt"
"io"
)

// FrameHeaderSize — фиксированный размер заголовка кадра.
const FrameHeaderSize = 12

// MaxDataPayload — верхняя граница payload для DATA.
const MaxDataPayload = 16384

// MaxControlPayload — верхняя граница payload для control кадров.
const MaxControlPayload = 1 * 1024

// FrameType — тип кадра.
type FrameType uint8

const (
FrameSettings     FrameType = 0x01
FrameSettingsAck  FrameType = 0x02
FrameGoAway       FrameType = 0x03
FrameOpen         FrameType = 0x10
FrameOpenOK       FrameType = 0x11
FrameOpenErr      FrameType = 0x12
FrameFin          FrameType = 0x20
FrameReset        FrameType = 0x21
FrameData         FrameType = 0x30
FrameWindowUpdate FrameType = 0x31
FramePing         FrameType = 0x40
FramePong         FrameType = 0x41
FramePadding      FrameType = 0xF0
)

const SessionStreamID uint32 = 0

var ErrProtocol = errors.New("ghostmux: protocol error")
var ErrFrameTooLarge = errors.New("ghostmux: frame too large")
var ErrUnknownType = errors.New("ghostmux: unknown frame type")

// Frame — распарсенный кадр.
type Frame struct {
Type     FrameType
Flags    uint8
StreamID uint32
Payload  []byte
Padding  []byte // Искусственные байты для маскировки размера
}

func maxPayloadFor(t FrameType) uint32 {
switch t {
case FrameData:
return MaxDataPayload
case FrameSettings, FrameSettingsAck, FrameOpen, FrameOpenOK,
FrameOpenErr, FrameGoAway, FramePing, FramePong, FramePadding:
return MaxControlPayload
case FrameFin, FrameWindowUpdate:
		return 64
	case FrameReset:
		return MaxControlPayload
default:
return MaxControlPayload
}
}

func isKnownType(t FrameType) bool {
switch t {
case FrameSettings, FrameSettingsAck, FrameGoAway,
FrameOpen, FrameOpenOK, FrameOpenErr,
FrameFin, FrameReset,
FrameData, FrameWindowUpdate,
FramePing, FramePong,
FramePadding:
return true
default:
return false
}
}

func (f *Frame) Encode(buf []byte) error {
if len(buf) < FrameHeaderSize {
return fmt.Errorf("ghostmux: encode buffer too small: %d", len(buf))
}
if !isKnownType(f.Type) {
return fmt.Errorf("%w: 0x%02x", ErrUnknownType, uint8(f.Type))
}

totalLen := len(f.Payload) + len(f.Padding)
if uint64(totalLen) > uint64(maxPayloadFor(f.Type)) {
return fmt.Errorf("%w: type=0x%02x len=%d max=%d",
ErrFrameTooLarge, uint8(f.Type), totalLen, maxPayloadFor(f.Type))
}
if uint64(totalLen) > 0xFFFFFFFF {
return fmt.Errorf("ghostmux: payload length overflows uint32")
}
if len(f.Padding) > 0xFFFF {
return fmt.Errorf("ghostmux: padding length overflows uint16")
}

buf[0] = byte(f.Type)
buf[1] = f.Flags
binary.BigEndian.PutUint16(buf[2:4], uint16(len(f.Padding)))
binary.BigEndian.PutUint32(buf[4:8], f.StreamID)
binary.BigEndian.PutUint32(buf[8:12], uint32(totalLen))
return nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
var hdr [FrameHeaderSize]byte
if _, err := io.ReadFull(r, hdr[:]); err != nil {
return nil, err
}

t := FrameType(hdr[0])
flags := hdr[1]
paddingLen := binary.BigEndian.Uint16(hdr[2:4])
streamID := binary.BigEndian.Uint32(hdr[4:8])
totalLen := binary.BigEndian.Uint32(hdr[8:12])

if !isKnownType(t) {
return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownType, uint8(t))
}

max := maxPayloadFor(t)
if totalLen > max {
return nil, fmt.Errorf("%w: type=0x%02x len=%d max=%d",
ErrFrameTooLarge, uint8(t), totalLen, max)
}
if totalLen < uint32(paddingLen) {
return nil, fmt.Errorf("%w: totalLen < paddingLen", ErrProtocol)
}

var buf []byte
if totalLen > 0 {
buf = make([]byte, totalLen)
if _, err := io.ReadFull(r, buf); err != nil {
return nil, err
}
}

payloadLen := int(totalLen) - int(paddingLen)
return &Frame{
Type:     t,
Flags:    flags,
StreamID: streamID,
Payload:  buf[:payloadLen],
Padding:  buf[payloadLen:],
}, nil
}
