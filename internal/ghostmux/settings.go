package ghostmux

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Settings — параметры сессии, согласуемые в SETTINGS/SETTINGS_ACK.
//
// Локальные пределы всегда сильнее предложений удалённой стороны.
// Значения представлены как uint32, кодируются big-endian.
type Settings struct {
	// Version — версия протокола. Текущая: 1.
	Version uint8

	// MaxDataPayload — верхняя граница payload DATA, поддерживаемая
	// принимающей стороной.
	MaxDataPayload uint32

	// StreamRecvWindow — начальный per-stream receive credit.
	StreamRecvWindow uint32

	// SessionRecvWindow — начальный per-session receive credit.
	SessionRecvWindow uint32

	// MaxStreams — максимум одновременных потоков.
	MaxStreams uint32

	// Flags — зарезервировано для расширений. v1: 0.
	Flags uint32
}

// DefaultSettings — экспериментальные стартовые значения из PROTOCOL.md §9.
// Не оптимальные константы, подлежат уточнению после E0 benchmark.
func DefaultSettings() Settings {
	return Settings{
		Version:           1,
		MaxDataPayload:    MaxDataPayload,
		StreamRecvWindow:  2 * 1024 * 1024,
		SessionRecvWindow: 16 * 1024 * 1024,
		MaxStreams:        2048, // Увеличено с 64 до 2048 для YouTube/Telegram
		Flags:             0,
	}
}

// HardLimits — абсолютные пределы, которые нельзя превысить
// независимо от предложений peer.
type HardLimits struct {
	MaxDataPayload    uint32
	MaxStreamWindow   uint32
	MaxSessionWindow  uint32
	MaxStreamsPerSess uint32
}

// DefaultHardLimits — верхние границы, защищающие от злонамеренного peer.
func DefaultHardLimits() HardLimits {
	return HardLimits{
		MaxDataPayload:    MaxDataPayload,
		MaxStreamWindow:   4 * 1024 * 1024,
		MaxSessionWindow:  32 * 1024 * 1024,
		MaxStreamsPerSess: 4096, // Увеличено с 1024 до 4096 (должно быть >= MaxStreams)
	}
}

// settingsWireSize — размер закодированного SETTINGS в байтах.
// 1 (version) + 4 (flags) + 5 * 4 = 25.
const settingsWireSize = 25

// ErrSettingsMalformed — payload SETTINGS не того размера или с
// некорректными значениями.
var ErrSettingsMalformed = errors.New("ghostmux: malformed settings")

// Encode сериализует Settings в буфер длиной settingsWireSize.
func (s Settings) Encode() []byte {
	buf := make([]byte, settingsWireSize)
	buf[0] = s.Version
	binary.BigEndian.PutUint32(buf[1:5], s.Flags)
	binary.BigEndian.PutUint32(buf[5:9], s.MaxDataPayload)
	binary.BigEndian.PutUint32(buf[9:13], s.StreamRecvWindow)
	binary.BigEndian.PutUint32(buf[13:17], s.SessionRecvWindow)
	binary.BigEndian.PutUint32(buf[17:21], s.MaxStreams)
	return buf
}

// DecodeSettings разбирает payload SETTINGS.
//
// Проверки:
//   - точный размер payload;
//   - version == 1;
//   - значения не превышают HardLimits;
//   - ненулевые окна и лимиты.
//
// HardLimits передаётся вызывающим — локальные пределы сильнее.
func DecodeSettings(payload []byte, hard HardLimits) (Settings, error) {
	if len(payload) != settingsWireSize {
		return Settings{}, fmt.Errorf("%w: got %d bytes, want %d",
			ErrSettingsMalformed, len(payload), settingsWireSize)
	}

	s := Settings{
		Version:           payload[0],
		Flags:             binary.BigEndian.Uint32(payload[1:5]),
		MaxDataPayload:    binary.BigEndian.Uint32(payload[5:9]),
		StreamRecvWindow:  binary.BigEndian.Uint32(payload[9:13]),
		SessionRecvWindow: binary.BigEndian.Uint32(payload[13:17]),
		MaxStreams:        binary.BigEndian.Uint32(payload[17:21]),
	}

	if s.Version != 1 {
		return Settings{}, fmt.Errorf("%w: unsupported version %d",
			ErrSettingsMalformed, s.Version)
	}
	if s.Flags != 0 {
		return Settings{}, fmt.Errorf("%w: flags must be 0 in v1, got 0x%x",
			ErrSettingsMalformed, s.Flags)
	}
	if s.MaxDataPayload == 0 || s.MaxDataPayload > hard.MaxDataPayload {
		return Settings{}, fmt.Errorf("%w: max_data_payload %d > hard limit %d",
			ErrSettingsMalformed, s.MaxDataPayload, hard.MaxDataPayload)
	}
	if s.StreamRecvWindow == 0 || s.StreamRecvWindow > hard.MaxStreamWindow {
		return Settings{}, fmt.Errorf("%w: stream_window %d > hard limit %d",
			ErrSettingsMalformed, s.StreamRecvWindow, hard.MaxStreamWindow)
	}
	if s.SessionRecvWindow == 0 || s.SessionRecvWindow > hard.MaxSessionWindow {
		return Settings{}, fmt.Errorf("%w: session_window %d > hard limit %d",
			ErrSettingsMalformed, s.SessionRecvWindow, hard.MaxSessionWindow)
	}
	if s.MaxStreams == 0 || s.MaxStreams > hard.MaxStreamsPerSess {
		return Settings{}, fmt.Errorf("%w: max_streams %d > hard limit %d",
			ErrSettingsMalformed, s.MaxStreams, hard.MaxStreamsPerSess)
	}
	return s, nil
}