package mask

import (
	"slices"
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
}

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
}
