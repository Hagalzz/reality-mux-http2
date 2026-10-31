package ghostmux

import (
	"bytes"
	"testing"
)

// FuzzEncodeReadRoundTrip проверяет, что любой корректно
// закодированный кадр читается обратно с теми же полями.
//
// Если Encode вернул nil, ReadFrame обязан вернуть тот же кадр.
// Иначе — баг.
func FuzzEncodeReadRoundTrip(f *testing.F) {
	f.Add(uint8(FrameData), uint32(1), []byte{})
	f.Add(uint8(FrameFin), uint32(3), []byte{})
	f.Add(uint8(FrameData), uint32(7), []byte{1, 2, 3, 4})
	f.Add(uint8(FrameReset), uint32(5), []byte{0xde, 0xad})
	f.Add(uint8(FrameWindowUpdate), uint32(9), []byte{0, 0, 1, 0})

	f.Fuzz(func(t *testing.T, ft uint8, sid uint32, payload []byte) {
		fr := &Frame{Type: FrameType(ft), StreamID: sid, Payload: payload}
		var hdr [FrameHeaderSize]byte
		if err := fr.Encode(hdr[:]); err != nil {
			t.Skip() // невалидный кадр — не наш case
		}
		full := append([]byte{}, hdr[:]...)
		full = append(full, payload...)

		got, err := ReadFrame(bytes.NewReader(full))
		if err != nil {
			t.Fatalf("ReadFrame after Encode: %v", err)
		}
		if got.Type != fr.Type || got.StreamID != fr.StreamID {
			t.Fatalf("mismatch type/id: %v/%d vs %v/%d",
				got.Type, got.StreamID, fr.Type, fr.StreamID)
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Fatalf("payload mismatch")
		}
	})
}
