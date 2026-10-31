package main

import (
"log"
"net"
"time"
)

// mute-target: принимает соединение и молчит. Для теста absolute pre-auth budget.
func main() {
ln, err := net.Listen("tcp", "127.0.0.1:9998")
if err != nil {
log.Fatal(err)
}
log.Printf("mute-target listening on 127.0.0.1:9998")
for {
c, err := ln.Accept()
if err != nil {
continue
}
log.Printf("mute-target: accepted %v", c.RemoteAddr())
go func(conn net.Conn) {
defer func() {
conn.Close()
log.Printf("mute-target: closed %v", conn.RemoteAddr())
}()
time.Sleep(60 * time.Second)
}(c)
}
}
