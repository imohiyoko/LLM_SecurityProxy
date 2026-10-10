// Package mask replaces sensitive substrings with placeholders.
package mask

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

// MinKnownLen is the shortest previously stored value that is masked by
// exact match. Shorter values would mask unrelated text.
const MinKnownLen = 6

// cacheMinLen: only strings at least this long are memoized. Conversation
// history is resent on every turn, so long tool results repeat constantly.
const cacheMinLen = 256

const cacheMaxEntries = 4096

// Stats counts masked values per kind.
type Stats map[string]int

// Masker is safe for concurrent use.
type Masker struct {
	det   *detect.Detector
	store *store.Store
	allow []*regexp.Regexp

	mu           sync.Mutex
	cache        map[string]cached
	cacheVersion uint64
}

type cached struct {
	out   string
	stats Stats
}

// New creates a masker. Values matching any allow pattern are never masked.
func New(det *detect.Detector, st *store.Store, allow []*regexp.Regexp) *Masker {
	return &Masker{det: det, store: st, allow: allow, cache: map[string]cached{}}
}

type span struct {
	start, end int
	kind       string
	keep       bool // existing placeholder: protect, do not mask
}

// String masks s and adds what it masked to stats.
func (m *Masker) String(s string, stats Stats) (string, error) {
	if s == "" {
		return s, nil
	}
	known, version := m.store.Known()

	if len(s) >= cacheMinLen {
		m.mu.Lock()
		if m.cacheVersion != version {
			m.cache = map[string]cached{}
			m.cacheVersion = version
		}
		c, ok := m.cache[s]
		m.mu.Unlock()
		if ok {
			for k, n := range c.stats {
				stats[k] += n
			}
			return c.out, nil
		}
	}

	local := Stats{}
	out, err := m.mask(s, known, local)
	if err != nil {
		return "", err
	}
	for k, n := range local {
		stats[k] += n
	}

	if len(s) >= cacheMinLen {
		// Masking may have stored new values; only cache against the version
		// that includes them, otherwise the next lookup recomputes anyway.
		_, after := m.store.Known()
		m.mu.Lock()
		if m.cacheVersion != after {
			m.cache = map[string]cached{}
			m.cacheVersion = after
		}
		if len(m.cache) >= cacheMaxEntries {
			m.cache = map[string]cached{}
		}
		m.cache[s] = cached{out: out, stats: local}
		m.mu.Unlock()
	}
	return out, nil
}

func (m *Masker) mask(s string, known []string, stats Stats) (string, error) {
	var spans []span
	for _, loc := range placeholder.Pattern.FindAllStringIndex(s, -1) {
		spans = append(spans, span{start: loc[0], end: loc[1], keep: true})
	}
	for _, d := range m.det.Find(s) {
		spans = append(spans, span{start: d.Start, end: d.End, kind: d.Kind})
	}
	// Values seen before, e.g. a secret the model wrote back into code after
	// we unmasked it, which no longer has the context a detector needs.
	for _, v := range known {
		if len(v) < MinKnownLen {
			break
		}
		for off := 0; ; {
			i := strings.Index(s[off:], v)
			if i < 0 {
				break
			}
			start := off + i
			spans = append(spans, span{start: start, end: start + len(v), kind: "KNOWN"})
			off = start + len(v)
		}
	}
	if len(spans) == 0 {
		return s, nil
	}

	// Protected spans win, then earlier, then longer.
	sort.Slice(spans, func(i, j int) bool {
		a, b := spans[i], spans[j]
		if a.keep != b.keep {
			return a.keep
		}
		if a.start != b.start {
			return a.start < b.start
		}
		return a.end-a.start > b.end-b.start
	})
	var chosen []span
	for _, sp := range spans {
		overlaps := false
		for _, c := range chosen {
			if sp.start < c.end && c.start < sp.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			chosen = append(chosen, sp)
		}
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].start < chosen[j].start })

	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, sp := range chosen {
		if sp.keep {
			continue
		}
		value := s[sp.start:sp.end]
		if m.allowed(value) {
			continue
		}
		id, kind, err := m.store.Put(sp.kind, value)
		if err != nil {
			return "", err
		}
		b.WriteString(s[last:sp.start])
		b.WriteString(placeholder.Format(kind, id))
		last = sp.end
		stats[kind]++
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

func (m *Masker) allowed(v string) bool {
	for _, re := range m.allow {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
