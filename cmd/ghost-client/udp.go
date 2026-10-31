package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ghostquic/ghost-quic-v2/internal/proxy"
	"github.com/ghostquic/ghost-quic-v2/internal/socks5"
)

type udpSession struct {
	cs   *proxy.ClientStream
	dest string
}

func handleSocksUDP(c net.Conn, ch *proxy.ClientHandler, req *socks5.Request) {
	// 1. Слушаем локальный UDP порт для приема датаграмм от клиента
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("udp listen: %v", err)
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, nil)
		return
	}
	defer udpConn.Close()

	// 2. Отвечаем клиенту адресом нашего UDP-сокета
	if err := socks5.WriteReply(c, socks5.RepSuccess, udpConn.LocalAddr()); err != nil {
		return
	}

	// 3. Следим за TCP-соединением. Пока оно открыто — сессия жива. Закрылось — гасим всё.
	go func() {
		_, _ = io.Copy(io.Discard, c)
		udpConn.Close()
		c.Close()
	}()

	// Карта активных UDP-стримов: destAddr -> stream
	streams := make(map[string]*proxy.ClientStream)
	var mu sync.Mutex

	defer func() {
		mu.Lock()
		for _, cs := range streams {
			cs.Close()
		}
		mu.Unlock()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 10 {
			continue
		}

		// Парсим SOCKS5 UDP заголовок
		// RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT
		atyp := buf[3]
		var host string
		var port uint16
		var offset int

		if atyp == 0x01 { // IPv4
			host = net.IP(buf[4:8]).String()
			port = binary.BigEndian.Uint16(buf[8:10])
			offset = 10
		} else if atyp == 0x03 { // Domain
			l := int(buf[4])
			host = string(buf[5 : 5+l])
			port = binary.BigEndian.Uint16(buf[5+l : 7+l])
			offset = 7 + l
		} else if atyp == 0x04 { // IPv6
			host = net.IP(buf[4:20]).String()
			port = binary.BigEndian.Uint16(buf[20:22])
			offset = 22
		} else {
			continue
		}

		dest := net.JoinHostPort(host, strconv.Itoa(int(port)))
		payload := buf[offset:n]

		mu.Lock()
		cs, ok := streams[dest]
		if !ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			newCs, err := ch.OpenUDP(ctx, host, port)
			cancel()
			if err == nil {
				cs = newCs
				streams[dest] = cs
				// Запускаем чтение из этого стрима и отправку клиенту
				go func(d string, cs *proxy.ClientStream) {
					rbuf := make([]byte, 64*1024)
					for {
						rn, rerr := cs.Read(rbuf)
						if rerr != nil {
							break
						}
						// Формируем ответный SOCKS5 UDP заголовок
						hdr := []byte{0, 0, 0} // RSV, FRAG
						// Мы отдаем обратно тот же адрес, с которого пришло
						// Для простоты парсим d и собираем заголовок
						dh, dp, _ := net.SplitHostPort(d)
						ip := net.ParseIP(dh)
						if ip != nil && ip.To4() != nil {
							hdr = append(hdr, 0x01)
							hdr = append(hdr, ip.To4()...)
						} else if ip != nil {
							hdr = append(hdr, 0x04)
							hdr = append(hdr, ip.To16()...)
						} else {
							hdr = append(hdr, 0x03, byte(len(dh)))
							hdr = append(hdr, []byte(dh)...)
						}
						p, _ := strconv.Atoi(dp)
						hdr = append(hdr, byte(p>>8), byte(p))
						out := append(hdr, rbuf[:rn]...)
						udpConn.WriteToUDP(out, clientAddr)
					}
				}(dest, cs)
			}
		}
		mu.Unlock()

		if cs != nil {
			_, _ = cs.Write(payload)
		}
	}
}