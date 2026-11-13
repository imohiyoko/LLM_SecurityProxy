// Package detect finds sensitive substrings in text.
//
// Rules are defined as data (see package rules); this package only runs them.
package detect

import (
	"regexp"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/field"
)

// Match is a sensitive span in the input, as byte offsets.
type Match struct {
	Start, End int
	Kind       string
	// Rule is the full ID of the rule that matched, e.g. "builtin/pii:email".
	Rule string
	// Field is set for a field rule match: the whole value of a field, which
	// may contain other matches. Callers give it the lowest priority.
	Field bool
	// Redact is set when the rule's mode is redact: the value is replaced by
	// a token that is never stored or restored. KeepFirst and KeepLast are
	// the letters and digits shown from each end.
	Redact              bool
	KeepFirst, KeepLast int
}

// Rule is a single compiled detector.
type Rule struct {
	// ID is "<ruleset id>:<rule id>".
	ID string
	// Kind is the label written into the placeholder.
	Kind string
	// Re is the pattern; nil when Keys is set.
	Re *regexp.Regexp
	// Keys, when set, makes this a field rule: it matches the whole value
	// of any field whose name is in the set (see package field).
	Keys *field.KeySet
	// Group selects the capture group to mask; 0 masks the whole match.
	Group int
	// Groups, when set, replaces Group: the first listed group that took
	// part in the match is masked.
	Groups []int
	// Allow lists patterns; a value matching any of them is not masked.
	Allow []*regexp.Regexp
	// Validators must all return true for the value to be masked.
	Validators []func(value string) bool
	// Tiers, when set, add the label of the first tier the value falls into
	// to Kind (see Tier).
	Tiers []Tier
	// Mode says how a match is masked (see Mode).
	Mode Mode
	// KeepFirst and KeepLast are the letters and digits a redacted value
	// shows from each end.
	KeepFirst, KeepLast int
	// ApproxDigits is the number of significant digits ModeApproximate
	// keeps.
	ApproxDigits int
}

// Mode is how a rule masks what it matches.
type Mode int

const (
	// ModeRestore replaces the value by a placeholder, stores it and
	// restores it in the response. It is the default.
	ModeRestore Mode = iota
	// ModeRedact replaces the value by a token that holds no reference to
	// it. The value is not stored and never comes back: for values the agent
	// should never need, such as card numbers.
	ModeRedact
	// ModeApproximate is ModeRestore with the amount, rounded, in the kind
	// (SALARY_ABOUT_4500K), so the model can reason with its size.
	ModeApproximate
)

// match builds a match of r for value v.
func (r *Rule) match(start, end int, v string, field bool) Match {
	return Match{
		Start: start, End: end, Kind: r.kindFor(v), Rule: r.ID, Field: field,
		Redact: r.Mode == ModeRedact, KeepFirst: r.KeepFirst, KeepLast: r.KeepLast,
	}
}

// Detector runs a set of rules.
type Detector struct {
	rules []Rule
}

// New builds a detector.
func New(rules []Rule) *Detector {
	return &Detector{rules: rules}
}

// Rules returns the rules the detector runs.
func (d *Detector) Rules() []Rule { return d.rules }

// Find returns every match of every rule. Matches may overlap; callers resolve.
func (d *Detector) Find(s string) []Match {
	var out []Match
	var fields []field.Field
	scanned := false
	for _, r := range d.rules {
		if r.Keys != nil {
			if !scanned {
				fields, scanned = field.Find(s), true
			}
			for _, f := range fields {
				if m, ok := r.field(f.Key, s[f.Start:f.End]); ok {
					m.Start, m.End = f.Start, f.End
					out = append(out, m)
				}
			}
			continue
		}
		for _, idx := range r.Re.FindAllStringSubmatchIndex(s, -1) {
			g := r.Group
			for _, c := range r.Groups {
				if g = c; idx[2*c] >= 0 {
					break
				}
			}
			start, end := idx[2*g], idx[2*g+1]
			if start < 0 || start == end {
				continue
			}
			if !r.accepts(s[start:end]) {
				continue
			}
			out = append(out, r.match(start, end, s[start:end], false))
		}
	}
	return out
}

// Field returns the field rules that match value as the value of a field
// named key, as whole-value matches. It is for values whose field name is
// known from structure (a JSON object member) rather than read from text.
func (d *Detector) Field(key, value string) []Match {
	if value == "" {
		return nil
	}
	k := field.NewKey(key)
	var out []Match
	for _, r := range d.rules {
		if m, ok := r.field(k, value); ok {
			out = append(out, m)
		}
	}
	return out
}

// field matches value as the value of a field with key k: the whole value,
// from 0 to len(value).
func (r *Rule) field(k field.Key, value string) (Match, bool) {
	if r.Keys == nil || !r.Keys.Has(k) || !r.accepts(value) {
		return Match{}, false
	}
	return r.match(0, len(value), value, true), true
}

func (r *Rule) accepts(v string) bool {
	for _, a := range r.Allow {
		if a.MatchString(v) {
			return false
		}
	}
	for _, ok := range r.Validators {
		if !ok(v) {
			return false
		}
	}
	return true
}
