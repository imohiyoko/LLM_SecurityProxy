// Package field finds values assigned to named fields in text, and matches
// field names against key sets however they are spelled.
package field

import (
	"fmt"
	"strings"
	"unicode"
)

// Normalize splits a field name into lower-case words, so that userName,
// user_name, user-name, USER_NAME, "user name" and user.name all become
// "user name". Words are split on any character that is not a letter or a
// digit, and on camelCase boundaries: a lower-case letter or digit followed
// by an upper-case one (userName), and the last letter of an upper-case run
// followed by a lower-case one (XMLName -> xml name). Digits stay with the
// word before them (address1, user2Name -> user2 name).
func Normalize(name string) string {
	rs := []rune(name)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, unicode.ToLower(r))
	}
	flush()
	return strings.Join(words, " ")
}

// Key is a field name prepared for matching: its normalised words joined
// without spaces, and the same for the last segment of a dotted path.
type Key struct {
	whole, last string
}

// NewKey prepares name for KeySet.Has.
func NewKey(name string) Key {
	k := Key{whole: joined(name)}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		k.last = joined(name[i+1:])
	}
	return k
}

// joined is Normalize without the spaces, so that names written as one
// word in any case (username, DISPLAYNAME, givenname) compare equal to their
// separated spellings.
func joined(name string) string { return strings.ReplaceAll(Normalize(name), " ", "") }

// KeySet is a set of field names, compared after Normalize with the word
// boundaries removed.
type KeySet struct {
	keys map[string]bool
}

// NewKeySet builds a key set. Each key may be written in any spelling
// (user_name, userName, username, "user name").
func NewKeySet(keys []string) (*KeySet, error) {
	ks := &KeySet{keys: map[string]bool{}}
	for _, k := range keys {
		n := joined(k)
		if n == "" {
			return nil, fmt.Errorf("key %q has no letters or digits", k)
		}
		ks.keys[n] = true
	}
	if len(ks.keys) == 0 {
		return nil, fmt.Errorf("no keys")
	}
	return ks, nil
}

// Has reports whether k is in the set. The whole name must match: a longer
// name that merely contains a key (billing_user_name, userNameKana) does not.
// A dotted path (self.user_name, profile.displayName) also matches on its
// last segment, the field itself.
func (ks *KeySet) Has(k Key) bool {
	return ks.keys[k.whole] || k.last != "" && ks.keys[k.last]
}

// Match is Has(NewKey(name)).
func (ks *KeySet) Match(name string) bool { return ks.Has(NewKey(name)) }
