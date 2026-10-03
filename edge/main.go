// Command edge is a fingerprinting TLS reverse proxy. It terminates TLS and
// HTTP/2 itself so it can observe what an ASGI app never sees (ClientHello,
// SETTINGS/WINDOW_UPDATE/PRIORITY frames, HPACK header order) and forwards the
// derived fingerprints to the upstream as x-* headers.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// Injected header names. All are stripped from inbound requests (anti-spoofing).
const (
	hJA3       = "x-ja3"
	hJA3Hash   = "x-ja3-hash"
	hJA4       = "x-ja4"
	hJA3Grease = "x-ja3-grease"
	hTLSExts   = "x-tls-exts"
	hTLSGroups = "x-tls-groups"
	hTLSSigAlg = "x-tls-sigalgs"
	hTLSALPN   = "x-tls-alpn"
	hTLSALPS   = "x-tls-alps"
	hH2        = "x-h2-fingerprint"
	hH2Labeled = "x-h2-fingerprint-labeled"
	hH2HdrPri  = "x-h2-headers-priority"
	hOrder     = "x-header-order"
	hProto     = "x-http-proto"
	hClientIP  = "x-client-ip"
)

var injected = []string{
	hJA3, hJA3Hash, hJA4, hJA3Grease, hTLSExts, hTLSGroups, hTLSSigAlg, hTLSALPN, hTLSALPS,
	hH2, hH2Labeled, hH2HdrPri, hOrder, hProto, hClientIP,
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	health := flag.Bool("healthcheck", false, "dial the local listener and exit 0/1")
	flag.Parse()
	listen := getenv("LISTEN", ":8443")
	if *health {
		os.Exit(healthcheck(listen))
	}

	upstream, err := url.Parse(getenv("UPSTREAM", "http://api:8000"))
	if err != nil {
		log.Fatalf("bad UPSTREAM: %v", err)
	}
	cert, err := loadOrGenerateCert(getenv("CERT_FILE", "/certs/tls.crt"), getenv("KEY_FILE", "/certs/tls.key"))
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}

	e := &edge{proxy: newProxy(upstream), h1: newChanListener()}
	h1srv := &http.Server{
		Handler:           http.HandlerFunc(e.serveH1),
		ConnContext:       func(ctx contextT, c net.Conn) contextT { return withH1Conn(ctx, c) },
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { log.Fatal(h1srv.Serve(e.h1)) }()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("edge listening on %s (TLS, h2+http/1.1) -> %s", listen, upstream)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go e.handleConn(c, tlsCfg)
	}
}

// healthcheck completes a TLS handshake with the local listener.
func healthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c.Close()
	return 0
}

// recConn records bytes read until the handshake completes, so the raw
// ClientHello can be parsed after crypto/tls has consumed it.
type recConn struct {
	net.Conn
	buf  bytes.Buffer
	done bool
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.done && n > 0 && c.buf.Len() < 64<<10 {
		c.buf.Write(p[:n])
	}
	return n, err
}

// connInfo is the per-connection fingerprint material.
type connInfo struct {
	hello  *Hello
	ip     string
	proto  string
	h2     *H2Print
	h1conn *h1Conn
}

type edge struct {
	proxy *httputil.ReverseProxy
	h1    *chanListener
}

func (e *edge) handleConn(raw net.Conn, cfg *tls.Config) {
	rec := &recConn{Conn: raw}
	tc := tls.Server(rec, cfg)
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return
	}
	rec.done = true
	hello, err := ParseClientHello(rec.buf.Bytes())
	if err != nil {
		log.Printf("clienthello parse: %v", err)
		hello = &Hello{}
	}
	rec.buf = bytes.Buffer{}
	ip, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	info := &connInfo{hello: hello, ip: ip}

	if tc.ConnectionState().NegotiatedProtocol == "h2" {
		info.proto = "h2"
		e.serveH2Conn(tc, info)
		return
	}
	info.proto = "http/1.1"
	raw.SetDeadline(time.Time{})
	e.h1.push(newH1Conn(tc, info))
}

func (e *edge) serveH2Conn(tc *tls.Conn, info *connInfo) {
	defer tc.Close()
	tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	fp, buffered, err := sniffH2(tc)
	if err != nil {
		log.Printf("h2 sniff: %v", err)
		return
	}
	tc.SetDeadline(time.Time{})
	info.h2 = fp
	conn := &replayConn{Conn: tc, r: io.MultiReader(bytes.NewReader(buffered), tc)}
	srv := &http2.Server{}
	srv.ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Per-connection fingerprints; header order comes from the first
			// stream's HEADERS (x/net/http2 does not expose per-stream raw order).
			e.forward(w, r, info, fp.Order)
		}),
	})
}

func (e *edge) serveH1(w http.ResponseWriter, r *http.Request) {
	c := h1ConnFrom(r.Context())
	if c == nil {
		http.Error(w, "internal error", 500)
		return
	}
	e.forward(w, r, c.info, c.order())
}

// forward injects fingerprint headers and hands the request to the proxy.
func (e *edge) forward(w http.ResponseWriter, r *http.Request, info *connInfo, order []string) {
	for _, h := range injected { // anti-spoofing: drop client-supplied values
		r.Header.Del(h)
	}
	h := r.Header
	hl := info.hello
	h.Set(hJA3, hl.JA3())
	h.Set(hJA3Hash, hl.JA3Hash())
	h.Set(hJA4, hl.JA4())
	h.Set(hJA3Grease, map[bool]string{true: "1", false: "0"}[hl.HasGrease()])
	h.Set(hTLSExts, hl.ExtsWire())
	h.Set(hTLSGroups, hl.GroupsWire())
	h.Set(hTLSSigAlg, hl.SigAlgsWire())
	h.Set(hTLSALPN, hl.ALPNWire())
	h.Set(hTLSALPS, hl.ALPSWire())
	if info.h2 != nil {
		h.Set(hH2, info.h2.Canonical())
		h.Set(hH2Labeled, info.h2.Labeled())
		h.Set(hH2HdrPri, info.h2.HeadersPriorityWire())
	}
	h.Set(hOrder, strings.Join(order, ","))
	h.Set(hProto, info.proto)
	h.Set(hClientIP, info.ip)
	e.proxy.ServeHTTP(w, r)
}

// newProxy builds a streaming reverse proxy; FlushInterval -1 flushes every
// write immediately so SSE works.
func newProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			// Rewrite drops X-Forwarded-*; header values set on In were copied
			// into Out before this call, so nothing further is needed.
		},
		FlushInterval: -1,
		Transport: &http.Transport{
			ForceAttemptHTTP2:   false,
			DisableCompression:  true, // pass Accept-Encoding through untouched
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     60 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: %v", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}
