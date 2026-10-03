package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
)

type contextT = context.Context

type h1Key struct{}

// reqLine matches an HTTP/1.x request line at the start of a read.
var reqLine = regexp.MustCompile(`^[A-Z]{3,10} \S+ HTTP/1\.[01]\r\n`)

// h1Conn wraps a connection and captures the raw header block of each
// request as it is read, preserving original header order and casing.
// Heuristic: a read that starts with a request line begins a new request
// (bodies that look like request lines are not expected).
type h1Conn struct {
	net.Conn
	info *connInfo

	mu      sync.Mutex
	pending []byte
	names   []string
}

func newH1Conn(c net.Conn, info *connInfo) *h1Conn {
	h := &h1Conn{Conn: c, info: info}
	info.h1conn = h
	return h
}

func (c *h1Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observe(p[:n])
	}
	return n, err
}

func (c *h1Conn) observe(chunk []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		if len(c.pending) < 64<<10 {
			c.pending = append(c.pending, chunk...)
		}
	} else if reqLine.Match(chunk) {
		c.pending = append([]byte(nil), chunk...)
	} else {
		return
	}
	if i := bytes.Index(c.pending, []byte("\r\n\r\n")); i >= 0 {
		c.names = headerNames(c.pending[:i])
		c.pending = nil
	}
}

func (c *h1Conn) order() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
}

// headerNames extracts header names (original casing, wire order) from a raw
// header block that starts with the request line.
func headerNames(block []byte) []string {
	lines := strings.Split(string(block), "\r\n")
	var out []string
	for _, l := range lines[1:] {
		if l == "" || l[0] == ' ' || l[0] == '\t' { // skip obs-fold continuations
			continue
		}
		if i := strings.IndexByte(l, ':'); i > 0 {
			out = append(out, l[:i])
		}
	}
	return out
}

func withH1Conn(ctx context.Context, c net.Conn) context.Context {
	if h, ok := c.(*h1Conn); ok {
		return context.WithValue(ctx, h1Key{}, h)
	}
	return ctx
}

func h1ConnFrom(ctx context.Context) *h1Conn {
	h, _ := ctx.Value(h1Key{}).(*h1Conn)
	return h
}

// chanListener feeds already-handshaken connections to an http.Server.
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, errors.New("listener closed")
	}
}

func (l *chanListener) Close() error   { close(l.done); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }
