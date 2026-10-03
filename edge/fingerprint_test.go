package main

import (
	"bytes"
	"encoding/binary"
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

func TestH2Priority(t *testing.T) {
	fp := &H2Print{Settings: [][2]uint32{{3, 100}}, Priorities: []string{"3:0:0:201", "5:0:0:101"}, Pseudo: []string{"m", "p"}}
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
