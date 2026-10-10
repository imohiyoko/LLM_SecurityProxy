// Package placeholder defines the token format that stands in for a masked value.
//
// A placeholder looks like __LLMSP_EMAIL_0123456789ab__. It is a valid
// identifier in most programming languages, needs no escaping inside JSON or
// shell strings, and is unlikely to be rewritten by a model.
package placeholder

import (
	"regexp"
	"strings"
)

const (
	// Prefix starts every placeholder.
	Prefix = "__LLMSP_"
	// Suffix ends every placeholder.
	Suffix = "__"
	// IDLen is the number of lowercase hex characters in a placeholder ID.
	IDLen = 12
	// MaxKindLen bounds the kind segment.
	MaxKindLen = 32
	// MaxLen is the longest possible placeholder.
	MaxLen = len(Prefix) + MaxKindLen + 1 + IDLen + len(Suffix)
)

// Pattern matches a complete placeholder. Group 1 is the kind, group 2 the ID.
var Pattern = regexp.MustCompile(`__LLMSP_([A-Z0-9_]{1,32}?)_([0-9a-f]{12})__`)

// Format builds a placeholder from a kind and an ID.
func Format(kind, id string) string {
	return Prefix + NormalizeKind(kind) + "_" + id + Suffix
}

// NormalizeKind maps an arbitrary label to the [A-Z0-9_] alphabet.
func NormalizeKind(kind string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(kind) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	k := strings.Trim(b.String(), "_")
	if k == "" {
		k = "SECRET"
	}
	if len(k) > MaxKindLen {
		k = strings.TrimRight(k[:MaxKindLen], "_")
	}
	return k
}

// CouldBePrefix reports whether t is the beginning of some placeholder that
// has not been completed yet. Used to hold back stream tails.
func CouldBePrefix(t string) bool {
	if len(t) == 0 || len(t) >= MaxLen {
		return false
	}
	n := min(len(t), len(Prefix))
	if t[:n] != Prefix[:n] {
		return false
	}
	for i := n; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
