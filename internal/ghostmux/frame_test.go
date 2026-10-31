package ghostmux

import (
"bytes"
"encoding/binary"
"errors"
"io"
"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
payload := []byte("hello, ghost")
f := &Frame{
Type:     FrameData,
Flags:    0x03,
StreamID: 7,
Payload:  payload,
}

var buf [FrameHeaderSize]byte
if err := f.Encode(buf[:]); err != nil {
t.Fatalf("encode: %v", err)
}

full := append(buf[:], payload...)
got, err := ReadFrame(bytes.NewReader(full))
if err != nil {
t.Fatalf("read: %v", err)
}

if got.Type != f.Type || got.Flags != f.Flags ||
got.StreamID != f.StreamID || !bytes.Equal(got.Payload, payload) {
t.Fatalf("roundtrip mismatch: got=%+v want=%+v", got, f)
}
}

func TestEncodeRejectsUnknownType(t *testing.T) {
f := &Frame{Type: FrameType(0x99)}
var buf [FrameHeaderSize]byte
if err := f.Encode(buf[:]); !errors.Is(err, ErrUnknownType) {
t.Fatalf("want ErrUnknownType, got %v", err)
}
}

func TestEncodeRejectsOversizedPayload(t *testing.T) {
f := &Frame{
Type:    FrameData,
Payload: make([]byte, MaxDataPayload+1),
}
var buf [FrameHeaderSize]byte
if err := f.Encode(buf[:]); !errors.Is(err, ErrFrameTooLarge) {
t.Fatalf("want ErrFrameTooLarge, got %v", err)
}
}

func TestEncodeRejectsSmallBuffer(t *testing.T) {
f := &Frame{Type: FrameData}
var buf [FrameHeaderSize - 1]byte
if err := f.Encode(buf[:]); err == nil {
t.Fatal("want error for small buffer, got nil")
}
}

func TestReadFrameReservedNonZero(t *testing.T) {
var hdr [FrameHeaderSize]byte
hdr[0] = byte(FrameData)
binary.BigEndian.PutUint16(hdr[2:4], 0x0001) // reserved != 0

_, err := ReadFrame(bytes.NewReader(hdr[:]))
if !errors.Is(err, ErrProtocol) {
t.Fatalf("want ErrProtocol, got %v", err)
}
}

func TestReadFrameUnknownType(t *testing.T) {
var hdr [FrameHeaderSize]byte
hdr[0] = 0x99

_, err := ReadFrame(bytes.NewReader(hdr[:]))
if !errors.Is(err, ErrUnknownType) {
t.Fatalf("want ErrUnknownType, got %v", err)
}
}

func TestReadFrameOversizedLength(t *testing.T) {
var hdr [FrameHeaderSize]byte
hdr[0] = byte(FrameData)
binary.BigEndian.PutUint32(hdr[8:12], MaxDataPayload+1)

_, err := ReadFrame(bytes.NewReader(hdr[:]))
if !errors.Is(err, ErrFrameTooLarge) {
t.Fatalf("want ErrFrameTooLarge, got %v", err)
}
}

func TestReadFrameCleanEOF(t *testing.T) {
_, err := ReadFrame(bytes.NewReader(nil))
if !errors.Is(err, io.EOF) {
t.Fatalf("want io.EOF, got %v", err)
}
}

func TestReadFramePartialHeader(t *testing.T) {
_, err := ReadFrame(bytes.NewReader(make([]byte, FrameHeaderSize-1)))
if !errors.Is(err, io.ErrUnexpectedEOF) {
t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
}
}

func TestReadFramePartialPayload(t *testing.T) {
var hdr [FrameHeaderSize]byte
hdr[0] = byte(FrameData)
binary.BigEndian.PutUint32(hdr[8:12], 100) // payload length = 100

// отправляем заголовок и только 50 байт payload
stream := append(hdr[:], make([]byte, 50)...)
_, err := ReadFrame(bytes.NewReader(stream))
if !errors.Is(err, io.ErrUnexpectedEOF) {
t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
}
}

func TestReadFrameZeroPayload(t *testing.T) {
var hdr [FrameHeaderSize]byte
hdr[0] = byte(FrameFin)
binary.BigEndian.PutUint32(hdr[4:8], 3) // stream_id=3

f, err := ReadFrame(bytes.NewReader(hdr[:]))
if err != nil {
t.Fatalf("read: %v", err)
}
if f.Type != FrameFin || f.StreamID != 3 || len(f.Payload) != 0 {
t.Fatalf("unexpected frame: %+v", f)
}
}

func TestMaxPayloadPerType(t *testing.T) {
cases := []struct {
t   FrameType
max uint32
}{
{FrameData, MaxDataPayload},
{FrameOpen, MaxControlPayload},
{FrameFin, 64},
{FrameReset, 64},
{FrameWindowUpdate, 64},
}
for _, c := range cases {
if got := maxPayloadFor(c.t); got != c.max {
t.Errorf("maxPayloadFor(0x%02x) = %d, want %d",
uint8(c.t), got, c.max)
}
}
}
