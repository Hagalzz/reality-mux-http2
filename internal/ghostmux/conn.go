package ghostmux

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const DefaultMaxWriteBatch = 16

var zeroPad = make([]byte, 2048)

type FrameHandler interface {
	OnFrame(*Frame) error
}

type Conn struct {
	conn         net.Conn
	sess         *Session
	sched        *Scheduler
	maxBat       int
	paddingSpent int64

	writeMu sync.Mutex

	closeOnce sync.Once
	done      chan struct{}

	mu     sync.Mutex
	err    error
	closed bool

	loopsWG sync.WaitGroup
}

func NewConn(c net.Conn, sess *Session, sched *Scheduler, maxBatch int) *Conn {
	if maxBatch <= 0 {
		maxBatch = DefaultMaxWriteBatch
	}
	return &Conn{
		conn:   c,
		sess:   sess,
		sched:  sched,
		maxBat: maxBatch,
		done:   make(chan struct{}),
	}
}

// WriteFrame отправляет служебные кадры (OPEN, RESET, PING и т.д.) в Control-очередь.
func (c *Conn) WriteFrame(f *Frame) error {
	return c.sched.EnqueueControl(f)
}

// WriteData отправляет DATA или FIN в поточную очередь конкретного стрима.
func (c *Conn) WriteData(id uint32, f *Frame) error {
	return c.sched.EnqueueData(id, f)
}

// RegisterStream регистрирует очередь для нового стрима.
func (c *Conn) RegisterStream(id uint32, maxBytes int64, maxFrames int) error {
	return c.sched.RegisterStream(id, maxBytes, maxFrames)
}

// UnregisterStream удаляет очередь стрима.
func (c *Conn) UnregisterStream(id uint32) {
	c.sched.UnregisterStream(id)
}

func (c *Conn) Start(handler FrameHandler) {
	c.loopsWG.Add(2)
	go c.readLoop(handler)
	go c.writeLoop()
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		log.Printf("[MUX] Close() requested, err=%v", c.Err())
		close(c.done)
		c.sched.Close()
		err = c.conn.Close()
	})
	return err
}

func (c *Conn) Wait() error {
	c.loopsWG.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) Done() <-chan struct{} {
	return c.done
}

func (c *Conn) setErr(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

func (c *Conn) readLoop(handler FrameHandler) {
	defer c.loopsWG.Done()
	defer c.Close()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		f, err := ReadFrame(c.conn)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			log.Printf("[MUX] readLoop exit: type=%T err=%v", err, err)
			c.setErr(err)
			return
		}
		if handler == nil {
			continue
		}
		if err := handler.OnFrame(f); err != nil {
			log.Printf("[MUX] handler.OnFrame error (stream-level, continue): %v", err)
			continue
		}
	}
}

func (c *Conn) writeLoop() {
	defer c.loopsWG.Done()
	defer c.Close()

	for {
		batch, ok := c.sched.WaitForBatch(c.maxBat)
		if !ok {
			return
		}

		total := 0
		for _, f := range batch {
			total += FrameHeaderSize + len(f.Payload) + len(f.Padding)
		}
		buf := make([]byte, 0, total)
		for _, f := range batch {
			var hdr [FrameHeaderSize]byte
			if err := f.Encode(hdr[:]); err != nil {
				log.Printf("[MUX] writeLoop Encode exit: type=%T err=%v", err, err)
				c.setErr(fmt.Errorf("encode frame: %w", err))
				return
			}
			buf = append(buf, hdr[:]...)
			buf = append(buf, f.Payload...)
			buf = append(buf, f.Padding...)
		}

		if len(buf) == 0 {
			continue
		}

		c.writeMu.Lock()
		n, werr := c.conn.Write(buf)
		c.writeMu.Unlock()

		if werr != nil {
			if errors.Is(werr, net.ErrClosed) {
				return
			}
			log.Printf("[MUX] writeLoop exit: type=%T n=%d len=%d err=%v", werr, n, len(buf), werr)
			c.setErr(fmt.Errorf("write frame n=%d len=%d: %w", n, len(buf), werr))
			return
		}
		if n < len(buf) {
			log.Printf("[MUX] writeLoop short write: n=%d len=%d", n, len(buf))
			c.setErr(io.ErrShortWrite)
			return
		}
	}
}