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

// IDs is the set of placeholder IDs issued while masking one request. Only
// these may be restored in the response to that request: a placeholder is
// not a bearer token for its value in any other request.
type IDs map[string]bool

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
	ids   []string
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

// String masks s, adds what it masked to stats and the placeholder IDs it
// issued to ids. ids may be nil.
func (m *Masker) String(s string, stats Stats, ids IDs) (string, error) {
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
			addIDs(ids, c.ids)
			return c.out, nil
		}
	}

	local := Stats{}
	var issued []string
	out, err := m.mask(s, known, nil, local, &issued)
	if err != nil {
		return "", err
	}
	for k, n := range local {
		stats[k] += n
	}
	addIDs(ids, issued)

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
		m.cache[s] = cached{out: out, stats: local, ids: issued}
		m.mu.Unlock()
	}
	return out, nil
}

// Field masks value as the value of a field named key, where the name is
// known from structure (a JSON object member, a header, a query parameter)
// rather than written in the text. If a field rule matches the name, the
// whole value is masked; otherwise, or in addition, the value is masked as
// String would.
func (m *Masker) Field(key, value string, stats Stats, ids IDs) (string, error) {
	whole := m.det.Field(key, value)
	if len(whole) == 0 {
		return m.String(value, stats, ids)
	}
	known, _ := m.store.Known()
	local := Stats{}
	var issued []string
	out, err := m.mask(value, known, whole, local, &issued)
	if err != nil {
		return "", err
	}
	for k, n := range local {
		stats[k] += n
	}
	addIDs(ids, issued)
	return out, nil
}

func addIDs(ids IDs, add []string) {
	if ids == nil {
		return
	}
	for _, id := range add {
		ids[id] = true
	}
}

// mask masks s. extra are matches found by the caller, in addition to the
// detector's.
func (m *Masker) mask(s string, known []string, extra []detect.Match, stats Stats, issued *[]string) (string, error) {
	var spans []span
	// Only a placeholder this store issued, written exactly as issued, is
	// protected. Anything else of that shape is masked as a whole: its kind
	// segment can carry an uppercase token (an AWS key, say) that detectors
	// miss there, because `_` defeats their \b. Masking round-trips, so the
	// client still gets the text back unchanged.
	for _, sub := range placeholder.Pattern.FindAllStringSubmatchIndex(s, -1) {
		kind, id := s[sub[2]:sub[3]], s[sub[4]:sub[5]]
		if stored, ok := m.store.Kind(id); ok && stored == kind {
			spans = append(spans, span{start: sub[0], end: sub[1], keep: true})
		} else {
			spans = append(spans, span{start: sub[0], end: sub[1], kind: "SECRET"})
		}
	}
	for _, d := range append(m.det.Find(s), extra...) {
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
		*issued = append(*issued, id)
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
