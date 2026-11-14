package mask

import (
	"slices"
	"strings"
	"sync"
)

// knownIndex finds stored values in text in time that depends on the
// length of the text, not on how many values are stored. Every value of at
// least MinKnownLen bytes is filed in each form it is searched in (as is,
// and JSON-escaped). At each position of the text a scan looks up the next
// MinKnownLen bytes, and only for the lengths of the forms starting with
// them, the text of that length. Values that share a prefix, such as API
// keys of one provider, mostly share a length too, so the work per position
// stays small however many values there are.
//
// A lookup reads the whole candidate, so only forms of up to maxIndexedLen
// bytes are filed this way. Longer ones (private keys, long tokens) are few,
// and each is searched for on its own in time linear in the text however
// long the form is: a scan stays linear in the text for any mix of values.
type knownIndex struct {
	mu sync.RWMutex
	n  int // values of the store's known list filed so far
	// forms holds every filed form.
	forms map[string]struct{}
	// byPrefix maps the first MinKnownLen bytes of a form to the lengths of
	// the forms starting with them.
	byPrefix map[string][]int
	// pair has a bit set for the first two bytes of every filed form, so
	// most positions are passed over without a map lookup.
	pair [1 << 16 / 64]uint64
	// long holds the forms longer than maxIndexedLen.
	long []string
}

// maxIndexedLen is the longest form filed in byPrefix.
const maxIndexedLen = 128

// update files known[idx.n:]. known is the store's known list, which only
// grows.
func (idx *knownIndex) update(known []string) {
	idx.mu.RLock()
	n := idx.n
	idx.mu.RUnlock()
	if n >= len(known) {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.forms == nil {
		idx.forms, idx.byPrefix = map[string]struct{}{}, map[string][]int{}
	}
	for _, v := range known[min(idx.n, len(known)):] {
		if len(v) < MinKnownLen {
			continue
		}
		idx.add(v)
		if needsJSONEscape(v) {
			idx.add(jsonEscaped(v))
		}
	}
	idx.n = max(idx.n, len(known))
}

func (idx *knownIndex) add(form string) {
	if _, ok := idx.forms[form]; ok {
		return
	}
	idx.forms[form] = struct{}{}
	if len(form) > maxIndexedLen {
		idx.long = append(idx.long, form)
		return
	}
	p := form[:MinKnownLen]
	if !slices.Contains(idx.byPrefix[p], len(form)) {
		idx.byPrefix[p] = append(idx.byPrefix[p], len(form))
	}
	b := uint16(form[0])<<8 | uint16(form[1])
	idx.pair[b/64] |= 1 << (b % 64)
}

// find calls hit for every standalone occurrence of a filed form in s.
// Occurrences of the same form do not overlap: after one, the search for
// that form goes on at its end.
func (idx *knownIndex) find(s string, hit func(start, end int)) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if len(idx.forms) == 0 {
		return
	}
	var next map[string]int // form -> where its next occurrence may start
	for i := 0; i+MinKnownLen <= len(s); i++ {
		b := uint16(s[i])<<8 | uint16(s[i+1])
		if idx.pair[b/64]&(1<<(b%64)) == 0 {
			continue
		}
		for _, n := range idx.byPrefix[s[i:i+MinKnownLen]] {
			end := i + n
			if end > len(s) {
				continue
			}
			f := s[i:end]
			if _, ok := idx.forms[f]; !ok || i < next[f] || !standalone(s, i, end) {
				continue
			}
			if next == nil {
				next = map[string]int{}
			}
			next[f] = end
			hit(i, end)
		}
	}
	for _, f := range idx.long {
		// Most texts hold none of the long forms; strings.Index tells so in
		// one pass. Where one occurs, every occurrence, overlapping ones
		// included (a match next to a letter is not standalone, but the one
		// a byte later may be), is listed in one more pass.
		first := strings.Index(s, f)
		if first < 0 {
			continue
		}
		next := 0
		occurrences(s[first:], f, func(i int) {
			start := first + i
			if end := start + len(f); start >= next && standalone(s, start, end) {
				hit(start, end)
				next = end
			}
		})
	}
}

// occurrences calls at with the start of every occurrence of f in s,
// overlapping ones included, in order, in time linear in len(s)+len(f)
// (Knuth-Morris-Pratt).
func occurrences(s, f string, at func(int)) {
	fail := make([]int32, len(f))
	for i, k := 1, int32(0); i < len(f); i++ {
		for k > 0 && f[i] != f[k] {
			k = fail[k-1]
		}
		if f[i] == f[k] {
			k++
		}
		fail[i] = k
	}
	for i, k := 0, int32(0); i < len(s); i++ {
		for k > 0 && s[i] != f[k] {
			k = fail[k-1]
		}
		if s[i] == f[k] {
			k++
		}
		if int(k) == len(f) {
			at(i + 1 - len(f))
			k = fail[k-1]
		}
	}
}
