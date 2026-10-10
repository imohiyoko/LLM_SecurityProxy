// Package detect finds sensitive substrings in text.
package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Match is a sensitive span in the input, as byte offsets.
type Match struct {
	Start, End int
	Kind       string
}

// Rule is a single detector.
type Rule struct {
	// Name identifies the rule in configuration (enable / disable).
	Name string
	// Kind is the label written into the placeholder.
	Kind string
	Re   *regexp.Regexp
	// Group selects the capture group to mask; 0 masks the whole match.
	Group int
	// Validate, if set, must return true for the value to be masked.
	Validate func(value string) bool
	// Optional rules are off unless enabled in configuration.
	Optional bool
}

// Detector runs a set of rules.
type Detector struct {
	rules []Rule
}

// New builds a detector from the built-in rules plus extra rules.
// enable turns on optional built-in rules; disable turns off any built-in rule.
func New(enable, disable []string, extra []Rule) (*Detector, error) {
	builtin := Builtin()
	known := map[string]bool{}
	for _, r := range builtin {
		known[r.Name] = true
	}
	on := map[string]bool{}
	for _, n := range enable {
		if !known[n] {
			return nil, fmt.Errorf("detect: unknown rule %q in enable", n)
		}
		on[n] = true
	}
	off := map[string]bool{}
	for _, n := range disable {
		if !known[n] {
			return nil, fmt.Errorf("detect: unknown rule %q in disable", n)
		}
		off[n] = true
	}
	var rules []Rule
	for _, r := range builtin {
		if off[r.Name] || (r.Optional && !on[r.Name]) {
			continue
		}
		rules = append(rules, r)
	}
	rules = append(rules, extra...)
	return &Detector{rules: rules}, nil
}

// Find returns every match of every rule. Matches may overlap; callers resolve.
func (d *Detector) Find(s string) []Match {
	var out []Match
	for _, r := range d.rules {
		for _, idx := range r.Re.FindAllStringSubmatchIndex(s, -1) {
			start, end := idx[2*r.Group], idx[2*r.Group+1]
			if start < 0 || start == end {
				continue
			}
			if r.Validate != nil && !r.Validate(s[start:end]) {
				continue
			}
			out = append(out, Match{Start: start, End: end, Kind: r.Kind})
		}
	}
	return out
}

// DictionaryRule masks any of the given literal values.
func DictionaryRule(name, kind string, values []string, caseInsensitive bool) (Rule, error) {
	var parts []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			parts = append(parts, regexp.QuoteMeta(v))
		}
	}
	if len(parts) == 0 {
		return Rule{}, fmt.Errorf("detect: dictionary %q has no values", name)
	}
	// Longest first so that "db.example" does not shadow "db.example.internal".
	sort.Slice(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	expr := "(?:" + strings.Join(parts, "|") + ")"
	if caseInsensitive {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return Rule{}, err
	}
	return Rule{Name: name, Kind: kind, Re: re}, nil
}
