package main

import (
"bytes"
"encoding/binary"
"io"
"math"
"net"
"strconv"
"sync/atomic"
"time"

"github.com/pires/go-proxyproto"
utls "github.com/refraction-networking/utls"
reality "github.com/xtls/reality"
)

// startAntiFingerprint — копия reality.DetectPostHandshakeRecordsLen,
// перенесённая в наш пакет из-за проблем с видимостью символа.
// startAntiFingerprint запускает детекторы и ждёт заполнения
// GlobalPostHandshakeRecordsLens до timeout. Возвращает true, если
// все ключи готовы.
func startAntiFingerprint(config reality.Config, timeout time.Duration) bool {
keys := []string{}
for sni := range config.ServerNames {
for alpn := range 3 {
key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
keys = append(keys, key)
if _, loaded := reality.GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
go detectPostHandshake(config, sni, alpn, key)
go detectCCS(config, sni, alpn, key)
}
}
}
deadline := time.Now().Add(timeout)
for time.Now().Before(deadline) {
allReady := true
for _, key := range keys {
val, ok := reality.GlobalPostHandshakeRecordsLens.Load(key)
if !ok {
allReady = false
break
}
if _, isBool := val.(bool); isBool {
allReady = false
break
}
}
if allReady {
return true
}
time.Sleep(50 * time.Millisecond)
}
return false
}

func detectPostHandshake(config reality.Config, sni string, alpn int, key string) {
defer func() {
val, _ := reality.GlobalPostHandshakeRecordsLens.Load(key)
if _, ok := val.(bool); ok {
reality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
}
}()
target, err := net.Dial(config.Type, config.Dest)
if err != nil {
return
}
detectConn := &reality.PostHandshakeRecordDetectConn{Conn: target, Key: key}
fp, protos := pickProfile(alpn)
uConn := utls.UClient(detectConn, &utls.Config{ServerName: sni, NextProtos: protos}, fp)
if err = uConn.Handshake(); err != nil {
return
}
io.Copy(io.Discard, uConn)
}

func detectCCS(config reality.Config, sni string, alpn int, key string) {
target, err := net.Dial(config.Type, config.Dest)
if err != nil {
return
}
if config.Xver == 1 || config.Xver == 2 {
if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
return
}
}
fp, protos := pickProfile(alpn)
conn := &reality.CCSDetectConn{Conn: target, Key: key}
uConn := utls.UClient(conn, &utls.Config{ServerName: sni, NextProtos: protos}, fp)
_ = uConn.Handshake()
}

func pickProfile(alpn int) (utls.ClientHelloID, []string) {
fp := utls.HelloChrome_Auto
protos := []string{"h2", "http/1.1"}
if alpn != 2 {
fp = utls.HelloGolang
}
if alpn == 1 {
protos = []string{"http/1.1"}
}
if alpn == 0 {
protos = nil
}
return fp, protos
}

// сохраняем ссылки, чтобы не выкинулись при линковке
var (
_ = bytes.Equal
_ = binary.BigEndian
_ = math.MaxInt
_ = atomic.Bool{}
_ = time.Second
)
