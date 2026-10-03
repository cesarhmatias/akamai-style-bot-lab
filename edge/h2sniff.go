package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// H2Print is the connection-level HTTP/2 fingerprint material.
type H2Print struct {
	Settings   [][2]uint32 // id,value in wire order
	WindowInc  uint32      // first WINDOW_UPDATE on stream 0 (0 if none)
	Priorities []string    // "stream:exclusive:dep:weight" per PRIORITY frame
	Pseudo     []string    // pseudo-header letters m,a,s,p in wire order
	Order      []string    // regular header names of the first HEADERS, wire order
}

// Canonical renders the Akamai text form: settings|window_update|priority|pseudo.
func (p *H2Print) Canonical() string {
	return p.format(false)
}

// Labeled renders S[...]|WU[...]|P[...]|PS[...].
func (p *H2Print) Labeled() string {
	return p.format(true)
}

func (p *H2Print) format(labeled bool) string {
	s := make([]string, len(p.Settings))
	for i, kv := range p.Settings {
		s[i] = fmt.Sprintf("%d:%d", kv[0], kv[1])
	}
	pr := "0"
	if len(p.Priorities) > 0 {
		pr = strings.Join(p.Priorities, ",")
	}
	parts := []string{strings.Join(s, ";"), strconv.FormatUint(uint64(p.WindowInc), 10), pr, strings.Join(p.Pseudo, ",")}
	if !labeled {
		return strings.Join(parts, "|")
	}
	return fmt.Sprintf("S[%s]|WU[%s]|P[%s]|PS[%s]", parts[0], parts[1], parts[2], parts[3])
}

// pseudoLetter maps a pseudo-header name to its Akamai letter.
func pseudoLetter(name string) string {
	switch name {
	case ":method":
		return "m"
	case ":authority":
		return "a"
	case ":scheme":
		return "s"
	case ":path":
		return "p"
	}
	return ""
}

// sniffH2 reads the client preface and frames up to and including the first
// complete header block, returning the fingerprint and every byte consumed so
// the caller can replay them to the real HTTP/2 server.
func sniffH2(c io.Reader) (*H2Print, []byte, error) {
	var raw bytes.Buffer
	r := io.TeeReader(c, &raw)
	pre := make([]byte, len(h2Preface))
	if _, err := io.ReadFull(r, pre); err != nil {
		return nil, raw.Bytes(), err
	}
	if string(pre) != h2Preface {
		return nil, raw.Bytes(), errors.New("h2: bad client preface")
	}
	fp := &H2Print{}
	var block []byte
	inBlock := false
	for {
		var hdr [9]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, raw.Bytes(), err
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		stream := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		if n > 1<<20 {
			return nil, raw.Bytes(), errors.New("h2: frame too large")
		}
		pl := make([]byte, n)
		if _, err := io.ReadFull(r, pl); err != nil {
			return nil, raw.Bytes(), err
		}
		switch {
		case inBlock && typ != 9:
			return nil, raw.Bytes(), errors.New("h2: expected CONTINUATION")
		case typ == 4 && flags&1 == 0: // SETTINGS (not ACK)
			for i := 0; i+6 <= len(pl); i += 6 {
				fp.Settings = append(fp.Settings, [2]uint32{
					uint32(binary.BigEndian.Uint16(pl[i:])), binary.BigEndian.Uint32(pl[i+2:])})
			}
		case typ == 8 && stream == 0 && len(pl) == 4: // WINDOW_UPDATE
			if fp.WindowInc == 0 {
				fp.WindowInc = binary.BigEndian.Uint32(pl) & 0x7fffffff
			}
		case typ == 2 && len(pl) == 5: // PRIORITY
			dep := binary.BigEndian.Uint32(pl)
			ex := dep >> 31
			fp.Priorities = append(fp.Priorities, fmt.Sprintf("%d:%d:%d:%d", stream, ex, dep&0x7fffffff, int(pl[4])+1))
		case typ == 1: // HEADERS
			frag := pl
			if flags&0x8 != 0 && len(frag) > 0 { // PADDED
				pad := int(frag[0])
				if 1+pad > len(frag) {
					return nil, raw.Bytes(), errors.New("h2: bad padding")
				}
				frag = frag[1 : len(frag)-pad]
			}
			if flags&0x20 != 0 { // PRIORITY
				if len(frag) < 5 {
					return nil, raw.Bytes(), errors.New("h2: short HEADERS")
				}
				frag = frag[5:]
			}
			block = append(block, frag...)
			inBlock = flags&0x4 == 0
		case typ == 9: // CONTINUATION
			block = append(block, pl...)
			inBlock = flags&0x4 == 0
		}
		if typ == 1 || typ == 9 {
			if !inBlock {
				if err := fp.decodeBlock(block); err != nil {
					return nil, raw.Bytes(), err
				}
				return fp, raw.Bytes(), nil
			}
		}
	}
}

func (p *H2Print) decodeBlock(block []byte) error {
	dec := hpack.NewDecoder(4096, nil)
	dec.SetEmitFunc(func(f hpack.HeaderField) {
		if strings.HasPrefix(f.Name, ":") {
			if l := pseudoLetter(f.Name); l != "" {
				p.Pseudo = append(p.Pseudo, l)
			}
			return
		}
		p.Order = append(p.Order, f.Name)
	})
	if _, err := dec.Write(block); err != nil {
		return err
	}
	return dec.Close()
}

// replayConn serves buffered bytes first, then the TLS connection. Embedding
// *tls.Conn keeps ConnectionState visible to x/net/http2.
type replayConn struct {
	*tls.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }
