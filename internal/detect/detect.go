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
			out = append(out, Match{Start: start, End: end, Kind: r.Kind, Rule: r.ID})
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
	return Match{End: len(value), Kind: r.Kind, Rule: r.ID, Field: true}, true
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
