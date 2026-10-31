package socks5

import (
	"bytes"
	"testing"
)

// FuzzReadRequest проверяет парсер SOCKS5 CONNECT.
//
// Ожидаемые классы: io.EOF, io.ErrUnexpectedEOF, ErrUnsupportedCommand,
// ErrUnsupportedAddress, ошибки версии.
// Паника, зависание, неограниченная аллокация — баг.
func FuzzReadRequest(f *testing.F) {
	// Корректный CONNECT IPv4 127.0.0.1:8080
	f.Add([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90})
	// CONNECT domain example.com:443
	f.Add(append([]byte{0x05, 0x01, 0x00, 0x03, 11}, append([]byte("example.com"), 0x01, 0xBB)...))
	// BIND (не поддерживается)
	f.Add([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90})
	// Неизвестный ATYP
	f.Add([]byte{0x05, 0x01, 0x00, 0x09, 0x00, 0x00})
	// Пустой domain
	f.Add([]byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = ReadRequest(r)
	})
}

// FuzzNegotiate проверяет negotiation-фазу.
func FuzzNegotiate(f *testing.F) {
	// no-auth
	f.Add([]byte{0x05, 0x01, 0x00})
	// user/pass only
	f.Add([]byte{0x05, 0x01, 0x02})
	// пустой список методов
	f.Add([]byte{0x05, 0x00})
	// неверная версия
	f.Add([]byte{0x04, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		var w bytes.Buffer
		_ = Negotiate(r, &w)
	})
}
