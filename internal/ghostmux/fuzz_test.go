package ghostmux

import (
	"bytes"
	"testing"
)

// FuzzReadFrame проверяет, что парсер кадра не паникует и не
// зависает на произвольном вводе.
//
// Ожидаемые классы ошибок:
//   - io.EOF — пустой ввод;
//   - io.ErrUnexpectedEOF — обрыв внутри заголовка или payload;
//   - ErrProtocol / ErrUnknownType / ErrFrameTooLarge — нарушение формата.
//
// Паника, зависание, неограниченная аллокация — баг.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})

	// Корректный DATA-кадр без payload.
	var dataHdr [FrameHeaderSize]byte
	fr := &Frame{Type: FrameData, StreamID: 1}
	if err := fr.Encode(dataHdr[:]); err != nil {
		f.Fatalf("seed encode: %v", err)
	}
	f.Add(dataHdr[:])

	// Корректный DATA с 4 байтами payload.
	withPayload := append([]byte{}, dataHdr[:]...)
	withPayload = append(withPayload, 0xde, 0xad, 0xbe, 0xef)
	withPayload[11] = 4
	f.Add(withPayload)

	// Неизвестный тип.
	f.Add([]byte{0xff, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})

	// reserved != 0.
	f.Add([]byte{0x30, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0})

	// length > max для типа.
	f.Add([]byte{0x30, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = ReadFrame(r)
	})
}
