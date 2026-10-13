// Package unmask restores placeholders to their original values, including
// across the chunk boundaries of a streamed response.
package unmask

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
)

// Resolver looks up the original value of a placeholder ID.
type Resolver interface {
	Resolve(id string) (string, bool)
}

// Escaper transforms a restored value before it is inserted.
type Escaper func(string) string

// Identity inserts values unchanged.
func Identity(s string) string { return s }

// JSONString escapes a value for insertion inside a JSON string literal.
// HTML characters (<, >, &) are kept as they are, so a restored value stays
// as close to its plain form as JSON allows.
func JSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return string(b[1 : len(b)-1])
}

// Replace restores every complete placeholder in s. Unknown IDs are left as is.
func Replace(s string, r Resolver, esc Escaper) (string, int) {
	if !strings.Contains(s, placeholder.Prefix) {
		return s, 0
	}
	n := 0
	out := placeholder.Pattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := placeholder.Pattern.FindStringSubmatch(m)
		v, ok := r.Resolve(sub[2])
		if !ok {
			return m
		}
		n++
		return esc(v)
	})
	return out, n
}

// Stream unmasks text that arrives in pieces. A tail that might be the start
// of a placeholder is held back until it is complete or ruled out.
type Stream struct {
	r     Resolver
	esc   Escaper
	buf   string
	Count int
}

// NewStream creates a stream unmasker.
func NewStream(r Resolver, esc Escaper) *Stream {
	return &Stream{r: r, esc: esc}
}

// Write consumes a chunk and returns the text that is safe to emit now.
func (s *Stream) Write(chunk string) string {
	buf := s.buf + chunk
	hold := holdIndex(buf)
	s.buf = buf[hold:]
	out, n := Replace(buf[:hold], s.r, s.esc)
	s.Count += n
	return out
}

// Flush returns everything still held.
func (s *Stream) Flush() string {
	out, n := Replace(s.buf, s.r, s.esc)
	s.Count += n
	s.buf = ""
	return out
}

// holdIndex returns the earliest offset whose suffix could still grow into a
// placeholder, or len(buf) if nothing needs holding.
func holdIndex(buf string) int {
	from := max(0, len(buf)-placeholder.MaxLen)
	// Scan a wider window so a complete placeholder that starts before from
	// is still recognised and not split.
	scan := max(0, from-placeholder.MaxLen)
	complete := placeholder.Pattern.FindAllStringIndex(buf[scan:], -1)
	for i := from; i < len(buf); i++ {
		if buf[i] != '_' {
			continue
		}
		inside := false
		for _, c := range complete {
			if scan+c[0] <= i && i < scan+c[1] {
				inside = true
				break
			}
		}
		if !inside && placeholder.CouldBePrefix(buf[i:]) {
			return i
		}
	}
	return len(buf)
}
