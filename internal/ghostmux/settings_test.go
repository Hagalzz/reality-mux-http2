package ghostmux

import (
"errors"
"testing"
)

func TestSettingsRoundtrip(t *testing.T) {
orig := DefaultSettings()
hard := DefaultHardLimits()

got, err := DecodeSettings(orig.Encode(), hard)
if err != nil {
t.Fatalf("decode: %v", err)
}
if got != orig {
t.Fatalf("roundtrip mismatch:\n got=%+v\nwant=%+v", got, orig)
}
}

func TestSettingsWrongSize(t *testing.T) {
hard := DefaultHardLimits()

cases := [][]byte{
nil,
make([]byte, settingsWireSize-1),
make([]byte, settingsWireSize+1),
}
for i, p := range cases {
_, err := DecodeSettings(p, hard)
if !errors.Is(err, ErrSettingsMalformed) {
t.Errorf("case %d: want ErrSettingsMalformed, got %v", i, err)
}
}
}

func TestSettingsBadVersion(t *testing.T) {
s := DefaultSettings()
s.Version = 2
_, err := DecodeSettings(s.Encode(), DefaultHardLimits())
if !errors.Is(err, ErrSettingsMalformed) {
t.Fatalf("want ErrSettingsMalformed, got %v", err)
}
}

func TestSettingsBadFlags(t *testing.T) {
s := DefaultSettings()
s.Flags = 0x01
_, err := DecodeSettings(s.Encode(), DefaultHardLimits())
if !errors.Is(err, ErrSettingsMalformed) {
t.Fatalf("want ErrSettingsMalformed, got %v", err)
}
}

func TestSettingsExceedsHardLimits(t *testing.T) {
hard := DefaultHardLimits()

cases := []struct {
name   string
mutate func(*Settings)
}{
{"max_data_payload", func(s *Settings) {
s.MaxDataPayload = hard.MaxDataPayload + 1
}},
{"stream_window", func(s *Settings) {
s.StreamRecvWindow = hard.MaxStreamWindow + 1
}},
{"session_window", func(s *Settings) {
s.SessionRecvWindow = hard.MaxSessionWindow + 1
}},
{"max_streams", func(s *Settings) {
s.MaxStreams = hard.MaxStreamsPerSess + 1
}},
}
for _, c := range cases {
s := DefaultSettings()
c.mutate(&s)
_, err := DecodeSettings(s.Encode(), hard)
if !errors.Is(err, ErrSettingsMalformed) {
t.Errorf("%s: want ErrSettingsMalformed, got %v", c.name, err)
}
}
}

func TestSettingsZeroValues(t *testing.T) {
hard := DefaultHardLimits()

cases := []struct {
name   string
mutate func(*Settings)
}{
{"max_data_payload", func(s *Settings) { s.MaxDataPayload = 0 }},
{"stream_window", func(s *Settings) { s.StreamRecvWindow = 0 }},
{"session_window", func(s *Settings) { s.SessionRecvWindow = 0 }},
{"max_streams", func(s *Settings) { s.MaxStreams = 0 }},
}
for _, c := range cases {
s := DefaultSettings()
c.mutate(&s)
_, err := DecodeSettings(s.Encode(), hard)
if !errors.Is(err, ErrSettingsMalformed) {
t.Errorf("%s: want ErrSettingsMalformed, got %v", c.name, err)
}
}
}

func TestErrorCodeString(t *testing.T) {
cases := map[ErrorCode]string{
CodeOK:            "OK",
CodeProtocolError: "PROTOCOL_ERROR",
CodeDialTimeout:   "DIAL_TIMEOUT",
CodeGoAway:        "GOAWAY",
}
for code, want := range cases {
if got := code.String(); got != want {
t.Errorf("ErrorCode(%d).String() = %q, want %q", code, got, want)
}
}
}

func TestErrorCodeKnown(t *testing.T) {
if !CodeGoAway.Known() {
t.Fatal("CodeGoAway should be known")
}
if ErrorCode(99).Known() {
t.Fatal("Code(99) should not be known")
}
}

func TestNewError(t *testing.T) {
e := NewError(CodeDialTimeout, "dial to %s timed out", "example.com")
if e.Code != CodeDialTimeout {
t.Errorf("code = %v, want %v", e.Code, CodeDialTimeout)
}
if want := "DIAL_TIMEOUT: dial to example.com timed out"; e.Error() != want {
t.Errorf("Error() = %q, want %q", e.Error(), want)
}
}
