package main

import (
"context"
"strings"
"testing"
"time"
)

func TestSafeDialRejectsNonPublic(t *testing.T) {
cases := []string{
"127.0.0.1:80",
"169.254.169.254:80",  // AWS metadata
"10.0.0.1:80",
"192.168.1.1:80",
"[::1]:80",
"[fe80::1]:80",
}

for _, addr := range cases {
ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
_, err := safeDialContext(ctx, "tcp", addr)
cancel()
if err == nil {
t.Errorf("%s: expected rejection, got nil", addr)
continue
}
if !strings.Contains(err.Error(), "non-public") {
t.Errorf("%s: expected 'non-public' error, got %v", addr, err)
}
t.Logf("%s: rejected (%v)", addr, err)
}
}

func TestSafeDialAllowsPublic(t *testing.T) {
// Проверяем, что публичный адрес не отклоняется на уровне Control.
// Реальный коннект может не пройти (например, порт закрыт) —
// важно, что ошибка НЕ про non-public.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_, err := safeDialContext(ctx, "tcp", "1.1.1.1:443")
if err != nil && strings.Contains(err.Error(), "non-public") {
t.Errorf("1.1.1.1 rejected as non-public: %v", err)
}
}
