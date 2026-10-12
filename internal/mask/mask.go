// Package mask replaces sensitive substrings with placeholders.
package mask

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

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
	cache        map[cacheKey]cached
	cacheVersion uint64
}

// cacheKey: a value masked as a field (Field with a matching rule) is cached
// apart from the same string masked on its own.
type cacheKey struct {
	field string
	s     string
}

type cached struct {
	out   string
	stats Stats
	ids   []string
}

// New creates a masker. Values matching any allow pattern are never masked.
func New(det *detect.Detector, st *store.Store, allow []*regexp.Regexp) *Masker {
	return &Masker{det: det, store: st, allow: allow, cache: map[cacheKey]cached{}}
}

type span struct {
	start, end int
	kind       string
	keep       bool // existing placeholder: protect, do not mask
	field      bool // whole value of a field: lowest priority, see mask
	escapes    bool // field value read from text: split at backslash escapes
}

// String masks s, adds what it masked to stats and the placeholder IDs it
// issued to ids. ids may be nil.
func (m *Masker) String(s string, stats Stats, ids IDs) (string, error) {
	return m.run(cacheKey{s: s}, nil, stats, ids)
}

// Field masks value as the value of a field named key, where the name is
// known from structure (a JSON object member, a header, a query parameter)
// rather than written in the text. If a field rule matches the name, the
// whole value is masked as well as anything String would mask in it.
func (m *Masker) Field(key, value string, stats Stats, ids IDs) (string, error) {
	whole := m.det.Field(key, value)
	ck := cacheKey{s: value}
	if len(whole) > 0 {
		ck.field = "\x00" + key // never equal to the empty field of String
	}
	return m.run(ck, whole, stats, ids)
}

// run masks ck.s with the extra matches found by the caller.
func (m *Masker) run(ck cacheKey, extra []detect.Match, stats Stats, ids IDs) (string, error) {
	s := ck.s
	if s == "" {
		return s, nil
	}
	known, version := m.store.Known()

	if len(s) >= cacheMinLen {
		m.mu.Lock()
		if m.cacheVersion != version {
			m.cache = map[cacheKey]cached{}
			m.cacheVersion = version
		}
		c, ok := m.cache[ck]
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
	out, err := m.mask(s, known, extra, local, &issued)
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
			m.cache = map[cacheKey]cached{}
			m.cacheVersion = after
		}
		if len(m.cache) >= cacheMaxEntries {
			m.cache = map[cacheKey]cached{}
		}
		m.cache[ck] = cached{out: out, stats: local, ids: issued}
		m.mu.Unlock()
	}
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

// mask masks s. extra are matches found by the caller from structure, in
// addition to the detector's.
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
	for _, d := range m.det.Find(s) {
		spans = append(spans, span{start: d.Start, end: d.End, kind: d.Kind, field: d.Field, escapes: d.Field})
	}
	for _, d := range extra {
		spans = append(spans, span{start: d.Start, end: d.End, kind: d.Kind, field: d.Field})
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
	// Allowed values are dropped before overlaps are resolved, so that an
	// allowed span never hides a secret inside it.
	var fields []span
	kept := spans[:0]
	for _, sp := range spans {
		switch {
		case !sp.keep && m.allowed(s[sp.start:sp.end]):
		case sp.field:
			fields = append(fields, sp)
		default:
			kept = append(kept, sp)
		}
	}
	spans = kept
	if len(spans) == 0 && len(fields) == 0 {
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
		if !overlapsAny(sp, chosen) {
			chosen = append(chosen, sp)
		}
	}
	// A field value is masked last, in what the other spans leave of it: it
	// can run past a secret it contains (a value cut short at `=` inside a
	// URL password) or around a placeholder, and masking it whole would drop
	// the other span and leave its tail in plaintext.
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].start != fields[j].start {
			return fields[i].start < fields[j].start
		}
		return fields[i].end-fields[i].start > fields[j].end-fields[j].start
	})
	for _, f := range fields {
		for _, p := range pieces(s, f, chosen) {
			if !m.allowed(s[p.start:p.end]) {
				chosen = append(chosen, p)
			}
		}
		// A value read from text holds its escapes (Jane \"JD\" Doe); store
		// it unescaped too, so the known-value pass finds it in decoded text.
		if v := s[f.start:f.end]; f.escapes && strings.ContainsRune(v, '\\') {
			if u := unescape(v); len(u) >= MinKnownLen {
				if _, _, err := m.store.Put(f.kind, u); err != nil {
					return "", err
				}
			}
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
		id, kind, err := m.store.Put(sp.kind, s[sp.start:sp.end])
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

func overlapsAny(sp span, chosen []span) bool {
	for _, c := range chosen {
		if sp.start < c.end && c.start < sp.end {
			return true
		}
	}
	return false
}

// pieces returns what is left of the field span f once the chosen spans are
// cut out of it, split at backslash escapes if f was read from text, and
// trimmed of spaces. Pieces without a letter or digit are dropped.
func pieces(s string, f span, chosen []span) []span {
	var out []span
	add := func(start, end int) {
		for start < end && (s[start] == ' ' || s[start] == '\t') {
			start++
		}
		for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
			end--
		}
		if strings.IndexFunc(s[start:end], func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0 {
			out = append(out, span{start: start, end: end, kind: f.kind})
		}
	}
	start := f.start
	for i := f.start; i < f.end; {
		if c, ok := covering(i, chosen); ok {
			add(start, i)
			i = min(c.end, f.end)
			start = i
			continue
		}
		if f.escapes && s[i] == '\\' && i+1 < f.end {
			add(start, i)
			_, w := utf8.DecodeRuneInString(s[i+1:])
			i += 1 + w
			start = i
			continue
		}
		i++
	}
	add(start, f.end)
	return out
}

func covering(i int, chosen []span) (span, bool) {
	for _, c := range chosen {
		if c.start <= i && i < c.end {
			return c, true
		}
	}
	return span{}, false
}

// unescape removes backslash escapes (\" \' \\).
func unescape(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func (m *Masker) allowed(v string) bool {
	for _, re := range m.allow {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
