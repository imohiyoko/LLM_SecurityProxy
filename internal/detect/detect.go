// Package detect finds sensitive substrings in text.
//
// Rules are defined as data (see package rules); this package only runs them.
package detect

import (
	"regexp"
)

// Match is a sensitive span in the input, as byte offsets.
type Match struct {
	Start, End int
	Kind       string
	// Rule is the full ID of the rule that matched, e.g. "builtin/pii:email".
	Rule string
}

// Rule is a single compiled detector.
type Rule struct {
	// ID is "<ruleset id>:<rule id>".
	ID string
	// Kind is the label written into the placeholder.
	Kind string
	Re   *regexp.Regexp
	// Group selects the capture group to mask; 0 masks the whole match.
	Group int
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
	for _, r := range d.rules {
		for _, idx := range r.Re.FindAllStringSubmatchIndex(s, -1) {
			start, end := idx[2*r.Group], idx[2*r.Group+1]
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
