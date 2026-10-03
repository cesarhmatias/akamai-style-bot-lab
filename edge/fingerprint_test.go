package main

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func u16b(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func ext(id uint16, data []byte) []byte {
	return append(u16b(id, uint16(len(data))), data...)
}

func lenPrefixed16(b []byte) []byte { return append(u16b(uint16(len(b))), b...) }

// fixtureHello builds a deterministic ClientHello record.
func fixtureHello() []byte {
	var exts []byte
	exts = append(exts, ext(0x0a0a, nil)...)
	exts = append(exts, ext(0, lenPrefixed16(append([]byte{0}, lenPrefixed16([]byte("localhost"))...)))...)
	exts = append(exts, ext(10, lenPrefixed16(u16b(0x0a0a, 29, 23)))...)
	exts = append(exts, ext(11, []byte{1, 0})...)
	exts = append(exts, ext(13, lenPrefixed16(u16b(0x0403, 0x0804)))...)
	exts = append(exts, ext(16, lenPrefixed16([]byte("\x02h2\x08http/1.1")))...)
	exts = append(exts, ext(43, append([]byte{6}, u16b(0x0a0a, 0x0304, 0x0303)...))...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id
	body = append(body, lenPrefixed16(u16b(0x0a0a, 0x1301, 0xc02b))...)
	body = append(body, 1, 0)
	body = append(body, lenPrefixed16(exts)...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// chromeLikeHello builds a Chrome-shaped hello: GREASE, ML-KEM group 4588, ALPS codepoint,
// ML-DSA-first signature algorithms and h2 ALPN. alps == 0 omits the ALPS extension.
func chromeLikeHello(alps uint16, groups []uint16, sigalgs []uint16) []byte {
	var exts []byte
	exts = append(exts, ext(0x0a0a, nil)...)
	exts = append(exts, ext(0, lenPrefixed16(append([]byte{0}, lenPrefixed16([]byte("localhost"))...)))...)
	exts = append(exts, ext(10, lenPrefixed16(u16b(groups...)))...)
	exts = append(exts, ext(13, lenPrefixed16(u16b(sigalgs...)))...)
	exts = append(exts, ext(16, lenPrefixed16([]byte("\x02h2\x08http/1.1")))...)
	if alps != 0 {
		exts = append(exts, ext(alps, lenPrefixed16(append([]byte{2}, []byte("h2")...)))...)
	}
	exts = append(exts, ext(43, append([]byte{6}, u16b(0x0a0a, 0x0304, 0x0303)...))...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, lenPrefixed16(u16b(0x0a0a, 0x1301, 0xc02b))...)
	body = append(body, 1, 0)
	body = append(body, lenPrefixed16(exts)...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestEraMarkerFields(t *testing.T) {
	raw := chromeLikeHello(17613, []uint16{0x2a2a, 0x11ec, 29, 23, 24}, []uint16{0x0904, 0x0905, 0x0906, 0x0403, 0x0804})
	h, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.GroupsWire(), "grease,4588,29,23,24"; got != want {
		t.Errorf("groups = %q want %q", got, want)
	}
	if got, want := h.SigAlgsWire(), "0904,0905,0906,0403,0804"; got != want {
		t.Errorf("sigalgs = %q want %q", got, want)
	}
	if got, want := h.ALPNWire(), "h2,http/1.1"; got != want {
		t.Errorf("alpn = %q want %q", got, want)
	}
	if got := h.ALPSWire(); got != "17613" {
		t.Errorf("alps = %q", got)
	}
}

func TestALPSVariants(t *testing.T) {
	groups := []uint16{29, 23}
	sig := []uint16{0x0403}
	for alps, want := range map[uint16]string{17513: "17513", 17613: "17613", 0: "none"} {
		h, err := ParseClientHello(chromeLikeHello(alps, groups, sig))
		if err != nil {
			t.Fatal(err)
		}
		if got := h.ALPSWire(); got != want {
			t.Errorf("alps(%d) = %q want %q", alps, got, want)
		}
	}
	// Kyber draft group 0x6399 (25497) is the pre-131 hybrid.
	h, _ := ParseClientHello(chromeLikeHello(17513, []uint16{0x6399, 29}, sig))
	if got := h.GroupsWire(); got != "25497,29" {
		t.Errorf("groups = %q", got)
	}
}

func TestConnIDDiffersPerHandshake(t *testing.T) {
	a := chromeLikeHello(17613, []uint16{29}, []uint16{0x0403})
	b := append([]byte(nil), a...)
	b[5+4+2] ^= 0xff // flip a byte of the client random
	ha, _ := ParseClientHello(a)
	hb, _ := ParseClientHello(b)
	if len(ha.ConnID()) != 12 || ha.ConnID() == hb.ConnID() {
		t.Errorf("conn ids %q %q", ha.ConnID(), hb.ConnID())
	}
	if (&Hello{}).ConnID() != "" {
		t.Error("empty hello must have no conn id")
	}
}

func TestEmptyHelloFields(t *testing.T) {
	h := &Hello{}
	if h.GroupsWire() != "" || h.SigAlgsWire() != "" || h.ALPNWire() != "" || h.ALPSWire() != "none" {
		t.Errorf("empty hello fields: %q %q %q %q", h.GroupsWire(), h.SigAlgsWire(), h.ALPNWire(), h.ALPSWire())
	}
}

// Anti-spoofing: client-supplied copies of every injected header are replaced by edge values.
func TestForwardStripsSpoofedHeaders(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	e := &edge{proxy: newProxy(u)}
	h, err := ParseClientHello(chromeLikeHello(17613, []uint16{0x11ec, 29}, []uint16{0x0403}))
	if err != nil {
		t.Fatal(err)
	}
	info := &connInfo{hello: h, ip: "10.0.0.9", proto: "h2", h2: &H2Print{HasWU: true, WindowInc: 15663105, Pseudo: []string{"m"}, HdrPri: "1:0:256"}}
	req := httptest.NewRequest("GET", "/", nil)
	for _, name := range injected {
		req.Header.Set(name, "spoofed")
	}
	e.forward(httptest.NewRecorder(), req, info, []string{"user-agent"})
	for _, name := range injected {
		if v := seen.Get(name); v == "spoofed" {
			t.Errorf("%s was not stripped", name)
		}
	}
	for name, want := range map[string]string{
		hTLSGroups: "4588,29", hTLSSigAlg: "0403", hTLSALPN: "h2,http/1.1", hTLSALPS: "17613",
		hH2HdrPri: "1:0:256", hClientIP: "10.0.0.9", hTLSConn: h.ConnID(),
	} {
		if got := seen.Get(name); got != want {
			t.Errorf("%s = %q want %q", name, got, want)
		}
	}
}

func TestJA3AndJA4(t *testing.T) {
	h, err := ParseClientHello(fixtureHello())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.JA3(), "771,4865-49195,0-10-11-13-16-43,29-23,0"; got != want {
		t.Errorf("ja3 = %q want %q", got, want)
	}
	// md5 of the string above (precomputed)
	if h.JA3Hash() != "87991a9b84cb5b4bc5f84c5ecad46032" {
		t.Errorf("bad hash %q", h.JA3Hash())
	}
	want := "t13d0206h2_777cda164f4b_fb71836bce29"
	if got := h.JA4(); got != want {
		t.Errorf("ja4 = %q want %q", got, want)
	}
	if !h.HasGrease() {
		t.Error("expected grease")
	}
	if got, want := h.ExtsWire(), "grease,0,10,11,13,16,43"; got != want {
		t.Errorf("exts = %q want %q", got, want)
	}
}

func TestParseTruncated(t *testing.T) {
	raw := fixtureHello()
	if _, err := ParseClientHello(raw[:len(raw)-10]); err == nil {
		t.Error("expected error on truncated hello")
	}
}

func frame(typ, flags byte, stream uint32, pl []byte) []byte {
	b := []byte{byte(len(pl) >> 16), byte(len(pl) >> 8), byte(len(pl)), typ, flags}
	b = binary.BigEndian.AppendUint32(b, stream)
	return append(b, pl...)
}

func TestH2Fingerprint(t *testing.T) {
	var settings []byte
	for _, kv := range [][2]uint32{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}} {
		settings = binary.BigEndian.AppendUint16(settings, uint16(kv[0]))
		settings = binary.BigEndian.AppendUint32(settings, kv[1])
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":authority", "x"}, {":scheme", "https"}, {":path", "/"}, {"User-Agent", "t"}, {"accept", "*/*"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	wu := binary.BigEndian.AppendUint32(nil, 15663105)
	var in bytes.Buffer
	in.WriteString(h2Preface)
	in.Write(frame(4, 0, 0, settings))
	in.Write(frame(8, 0, 0, wu))
	in.Write(frame(1, 5, 1, hb.Bytes()))

	fp, raw, err := sniffH2(bytes.NewReader(in.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, in.Bytes()) {
		t.Error("replay bytes differ")
	}
	if got, want := fp.Canonical(), "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"; got != want {
		t.Errorf("canonical = %q want %q", got, want)
	}
	if got, want := fp.Labeled(), "S[1:65536;2:0;4:6291456;6:262144]|WU[15663105]|P[0]|PS[m,a,s,p]"; got != want {
		t.Errorf("labeled = %q want %q", got, want)
	}
	if got := strings.Join(fp.Order, ","); got != "User-Agent,accept" {
		t.Errorf("order = %q", got)
	}
}

// Paper (Akamai 2017): WINDOW_UPDATE is "00" when the frame is absent.
func TestH2AbsentWindowUpdateIs00(t *testing.T) {
	fp := &H2Print{Settings: [][2]uint32{{3, 100}, {4, 65535}}, Pseudo: []string{"m", "s", "a", "p"}}
	if got, want := fp.Canonical(), "3:100;4:65535|00|0|m,s,a,p"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got, want := fp.Labeled(), "S[3:100;4:65535]|WU[00]|P[0]|PS[m,s,a,p]"; got != want {
		t.Errorf("labeled got %q want %q", got, want)
	}
	if fp.HeadersPriorityWire() != "none" {
		t.Errorf("hdr priority = %q", fp.HeadersPriorityWire())
	}
}

func TestH2HeadersPriorityRecorded(t *testing.T) {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":authority", "x"}, {":scheme", "https"}, {":path", "/"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	// PRIORITY flag (0x20): exclusive=1, dep=0, wire weight 255 -> printed 256.
	pri := append(binary.BigEndian.AppendUint32(nil, 1<<31), 255)
	var in bytes.Buffer
	in.WriteString(h2Preface)
	in.Write(frame(4, 0, 0, nil))
	in.Write(frame(1, 0x25, 1, append(pri, hb.Bytes()...)))
	fp, _, err := sniffH2(bytes.NewReader(in.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := fp.HeadersPriorityWire(); got != "1:0:256" {
		t.Errorf("hdr priority = %q", got)
	}
	if !strings.Contains(fp.Canonical(), "|00|") {
		t.Errorf("no WINDOW_UPDATE frame sent, want 00: %q", fp.Canonical())
	}
	if strings.Join(fp.Pseudo, ",") != "m,a,s,p" {
		t.Errorf("pseudo = %v (priority bytes must not corrupt the block)", fp.Pseudo)
	}
}

func TestH2Priority(t *testing.T) {
	fp := &H2Print{Settings: [][2]uint32{{3, 100}}, HasWU: true, Priorities: []string{"3:0:0:201", "5:0:0:101"}, Pseudo: []string{"m", "p"}}
	if got, want := fp.Canonical(), "3:100|0|3:0:0:201,5:0:0:101|m,p"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestHeaderNames(t *testing.T) {
	got := headerNames([]byte("GET / HTTP/1.1\r\nHost: a\r\nuser-AGENT: b\r\nAccept: c"))
	if strings.Join(got, ",") != "Host,user-AGENT,Accept" {
		t.Errorf("got %v", got)
	}
}
