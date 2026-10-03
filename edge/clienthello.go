package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Hello holds the fields of a TLS ClientHello that matter for fingerprinting.
// Lists keep wire order and still contain GREASE values; helpers filter them.
type Hello struct {
	Version     uint16 // legacy client_version
	Ciphers     []uint16
	Exts        []uint16 // extension ids in wire order
	Curves      []uint16 // supported_groups (10)
	Points      []uint8  // ec_point_formats (11)
	SigAlgs     []uint16 // signature_algorithms (13)
	ALPN        []string // application_layer_protocol_negotiation (16)
	SupVersions []uint16 // supported_versions (43)
	HasSNI      bool
	Random      []byte // client random (32 bytes); unique per connection
}

// isGrease reports whether v is a GREASE value (RFC 8701): 0x?a?a with equal bytes.
func isGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

var errShort = errors.New("clienthello: truncated")

// reader is a tiny bounds-checked cursor over a byte slice.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = errShort
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if b := r.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u24() int {
	if b := r.take(3); b != nil {
		return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	}
	return 0
}

// handshakeFromRecords concatenates handshake-record payloads from raw TLS
// records (a ClientHello may be fragmented over several records).
func handshakeFromRecords(raw []byte) ([]byte, error) {
	var hs []byte
	for len(raw) >= 5 {
		if raw[0] != 22 {
			return nil, errors.New("clienthello: not a handshake record")
		}
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+n {
			// Partial last record: use what we have, parse will report truncation.
			hs = append(hs, raw[5:]...)
			return hs, nil
		}
		hs = append(hs, raw[5:5+n]...)
		raw = raw[5+n:]
		if len(hs) >= 4 && len(hs) >= 4+int(hs[1])<<16|int(hs[2])<<8|int(hs[3]) {
			break
		}
	}
	if len(hs) == 0 {
		return nil, errShort
	}
	return hs, nil
}

// ParseClientHello parses raw bytes starting at the first TLS record header.
func ParseClientHello(raw []byte) (*Hello, error) {
	hs, err := handshakeFromRecords(raw)
	if err != nil {
		return nil, err
	}
	r := &reader{b: hs}
	if t := r.u8(); r.err == nil && t != 1 {
		return nil, errors.New("clienthello: not a ClientHello")
	}
	body := &reader{b: r.take(r.u24())}
	if r.err != nil {
		return nil, r.err
	}
	h := &Hello{Version: body.u16()}
	h.Random = append([]byte(nil), body.take(32)...) // random
	body.take(body.u8())                             // session id
	cs := &reader{b: body.take(int(body.u16()))}
	for len(cs.b) >= 2 && cs.err == nil {
		h.Ciphers = append(h.Ciphers, cs.u16())
	}
	body.take(body.u8()) // compression methods
	if body.err != nil {
		return nil, body.err
	}
	if len(body.b) == 0 {
		return h, nil // no extensions
	}
	exts := &reader{b: body.take(int(body.u16()))}
	for len(exts.b) > 0 && exts.err == nil {
		id := exts.u16()
		data := &reader{b: exts.take(int(exts.u16()))}
		if exts.err != nil {
			break
		}
		h.Exts = append(h.Exts, id)
		h.parseExt(id, data)
	}
	return h, exts.err
}

func (h *Hello) parseExt(id uint16, d *reader) {
	switch id {
	case 0: // server_name
		h.HasSNI = len(d.b) > 0
	case 10:
		l := &reader{b: d.take(int(d.u16()))}
		for len(l.b) >= 2 && l.err == nil {
			h.Curves = append(h.Curves, l.u16())
		}
	case 11:
		for _, b := range d.take(d.u8()) {
			h.Points = append(h.Points, b)
		}
	case 13:
		l := &reader{b: d.take(int(d.u16()))}
		for len(l.b) >= 2 && l.err == nil {
			h.SigAlgs = append(h.SigAlgs, l.u16())
		}
	case 16:
		l := &reader{b: d.take(int(d.u16()))}
		for len(l.b) > 0 && l.err == nil {
			h.ALPN = append(h.ALPN, string(l.take(l.u8())))
		}
	case 43:
		l := &reader{b: d.take(d.u8())}
		for len(l.b) >= 2 && l.err == nil {
			h.SupVersions = append(h.SupVersions, l.u16())
		}
	}
}

func dropGrease(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGrease(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinU16(in []uint16, sep string, f func(uint16) string) string {
	s := make([]string, len(in))
	for i, v := range in {
		s[i] = f(v)
	}
	return strings.Join(s, sep)
}

func dec(v uint16) string  { return strconv.Itoa(int(v)) }
func hex4(v uint16) string { return fmt.Sprintf("%04x", v) }

// HasGrease reports whether any GREASE value appears in ciphers or extensions.
func (h *Hello) HasGrease() bool {
	return len(dropGrease(h.Ciphers)) != len(h.Ciphers) ||
		len(dropGrease(h.Exts)) != len(h.Exts) ||
		len(dropGrease(h.Curves)) != len(h.Curves) ||
		len(dropGrease(h.SupVersions)) != len(h.SupVersions)
}

// JA3 returns the JA3 string: version,ciphers,extensions,curves,point formats
// with GREASE removed, values in decimal, lists joined by '-'.
func (h *Hello) JA3() string {
	pts := make([]string, len(h.Points))
	for i, p := range h.Points {
		pts[i] = strconv.Itoa(int(p))
	}
	return strings.Join([]string{
		dec(h.Version),
		joinU16(dropGrease(h.Ciphers), "-", dec),
		joinU16(dropGrease(h.Exts), "-", dec),
		joinU16(dropGrease(h.Curves), "-", dec),
		strings.Join(pts, "-"),
	}, ",")
}

// JA3Hash is the md5 hex digest of the JA3 string.
func (h *Hello) JA3Hash() string {
	sum := md5.Sum([]byte(h.JA3()))
	return hex.EncodeToString(sum[:])
}

// ExtsWire lists raw extension ids in wire order, GREASE shown as "grease".
func (h *Hello) ExtsWire() string {
	return joinU16(h.Exts, ",", func(v uint16) string {
		if isGrease(v) {
			return "grease"
		}
		return dec(v)
	})
}

// GroupsWire lists supported_groups in wire order, decimal, GREASE shown as "grease".
// Era marker: 4588 (0x11EC, X25519MLKEM768) means Chrome 131+, 25497 (0x6399, Kyber) pre-131.
func (h *Hello) GroupsWire() string {
	return joinU16(h.Curves, ",", func(v uint16) string {
		if isGrease(v) {
			return "grease"
		}
		return dec(v)
	})
}

// SigAlgsWire lists signature_algorithms as 4-digit hex in wire order (GREASE as "grease").
// Era marker: ML-DSA schemes 0904,0905,0906 first in a Chrome-shaped hello (Chrome 150+).
func (h *Hello) SigAlgsWire() string {
	return joinU16(h.SigAlgs, ",", func(v uint16) string {
		if isGrease(v) {
			return "grease"
		}
		return hex4(v)
	})
}

// ALPNWire lists the ALPN protocol names the client offered, in wire order.
func (h *Hello) ALPNWire() string {
	return strings.Join(h.ALPN, ",")
}

// ALPSWire reports the ALPS (application_settings) codepoint the client sent:
// "17613" (current, Chrome 133+), "17513" (legacy, Chrome <= 132) or "none".
func (h *Hello) ALPSWire() string {
	res := "none"
	for _, e := range h.Exts {
		switch e {
		case 17613:
			return "17613"
		case 17513:
			res = "17513"
		}
	}
	return res
}

// ConnID is a short opaque per-connection identifier: the first 12 hex digits of
// sha256(client random). The random is fresh for every handshake and is public on the wire, so
// requests on one (keep-alive or multiplexed) connection share a value and new connections
// differ. It lets the API count distinct connections (e.g. repeated extension order).
func (h *Hello) ConnID() string {
	if len(h.Random) == 0 {
		return ""
	}
	sum := sha256.Sum256(h.Random)
	return hex.EncodeToString(sum[:])[:12]
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// JA4 returns the FoxIO JA4 TLS-over-TCP fingerprint (a_b_c).
func (h *Hello) JA4() string {
	ver := "00"
	best := uint16(0)
	for _, v := range dropGrease(h.SupVersions) {
		if v > best {
			best = v
		}
	}
	if best == 0 {
		best = h.Version
	}
	switch best {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	case 0x0300:
		ver = "s3"
	case 0x0002:
		ver = "s2"
	}
	sni := "i"
	if h.HasSNI {
		sni = "d"
	}
	ciphers := dropGrease(h.Ciphers)
	exts := dropGrease(h.Exts)
	alpn := "00"
	if len(h.ALPN) > 0 && len(h.ALPN[0]) > 0 {
		first, last := h.ALPN[0][0], h.ALPN[0][len(h.ALPN[0])-1]
		if isAlnum(first) && isAlnum(last) {
			alpn = string([]byte{first, last})
		} else {
			alpn = fmt.Sprintf("%02x", first)[:1] + fmt.Sprintf("%02x", last)[1:]
		}
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	sc := append([]uint16(nil), ciphers...)
	sortU16(sc)
	b := "000000000000"
	if len(sc) > 0 {
		b = sha12(joinU16(sc, ",", hex4))
	}

	// Extensions sorted, minus SNI (0) and ALPN (16); signature algorithms keep wire order.
	var se []uint16
	for _, e := range exts {
		if e != 0 && e != 16 {
			se = append(se, e)
		}
	}
	sortU16(se)
	cin := joinU16(se, ",", hex4)
	if len(h.SigAlgs) > 0 {
		cin += "_" + joinU16(h.SigAlgs, ",", hex4)
	}
	c := "000000000000"
	if len(se) > 0 || len(h.SigAlgs) > 0 {
		c = sha12(cin)
	}
	return a + "_" + b + "_" + c
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func sortU16(s []uint16) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
