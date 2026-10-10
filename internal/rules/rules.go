// Package rules loads detection rulesets from YAML.
//
// A ruleset is a file with an ID and a list of rules; a rule is addressed as
// "<ruleset id>:<rule id>". Built-in rulesets are embedded in the binary and
// written in the same format as user rulesets. A user ruleset with the same ID
// as a built-in one replaces it.
package rules

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

var (
	setIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$`)
	ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// Ruleset is one YAML file.
type Ruleset struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	// Default is whether the ruleset is on unless configuration says otherwise.
	// Omitted means true.
	Default *bool  `yaml:"default"`
	Rules   []Spec `yaml:"rules"`

	// Source is where the ruleset was loaded from ("builtin" or a file path).
	Source string `yaml:"-"`
	dir    string
}

// Spec is one rule as written in YAML. Exactly one of Pattern or
// Values / ValuesFile must be set.
type Spec struct {
	ID          string `yaml:"id"`
	Kind        string `yaml:"kind"`
	Description string `yaml:"description"`
	// Pattern is an RE2 regular expression.
	Pattern string `yaml:"pattern"`
	// Group selects the capture group to mask; 0 masks the whole match.
	Group int `yaml:"group"`
	// Values are literal strings to mask.
	Values []string `yaml:"values"`
	// ValuesFile holds one literal per line, relative to the ruleset file.
	ValuesFile string `yaml:"values_file"`
	// CaseInsensitive applies to Values / ValuesFile.
	CaseInsensitive bool `yaml:"case_insensitive"`
	// Allow lists RE2 patterns; a matched value that matches any is not masked.
	Allow []string `yaml:"allow"`
	// Validators are named checks the value must pass (see Validators).
	Validators []string `yaml:"validators"`
	// Enabled omitted means true.
	Enabled *bool `yaml:"enabled"`
}

// Selection says which rulesets and rules are on. Entries are ruleset IDs
// ("builtin/pii") or rule IDs ("builtin/pii:email").
type Selection struct {
	Enable  []string
	Disable []string
}

// Catalog is every ruleset that was loaded, by ID.
type Catalog struct {
	Sets map[string]*Ruleset
}

// Load reads the built-in rulesets and then every *.yaml / *.yml file in dirs.
// Missing directories are skipped.
func Load(dirs []string) (*Catalog, error) {
	c := &Catalog{Sets: map[string]*Ruleset{}}

	entries, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	for _, name := range entries {
		b, err := builtinFS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		rs, err := parse(b, "builtin:"+path.Base(name), "")
		if err != nil {
			return nil, err
		}
		if _, dup := c.Sets[rs.ID]; dup {
			return nil, fmt.Errorf("rules: duplicate built-in ruleset %q", rs.ID)
		}
		rs.Source = "builtin"
		c.Sets[rs.ID] = rs
	}

	userSource := map[string]string{}
	for _, dir := range dirs {
		files, err := ruleFiles(dir)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			rs, err := parse(b, f, filepath.Dir(f))
			if err != nil {
				return nil, err
			}
			if prev, dup := userSource[rs.ID]; dup {
				return nil, fmt.Errorf("rules: ruleset %q defined in both %s and %s", rs.ID, prev, f)
			}
			userSource[rs.ID] = f
			rs.Source = f
			c.Sets[rs.ID] = rs // replaces a built-in ruleset with the same ID
		}
	}
	return c, nil
}

func ruleFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if !e.IsDir() && (ext == ".yaml" || ext == ".yml") && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

func parse(b []byte, source, dir string) (*Ruleset, error) {
	var rs Ruleset
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("rules: %s: %w", source, err)
	}
	if !setIDPattern.MatchString(rs.ID) {
		return nil, fmt.Errorf("rules: %s: invalid ruleset id %q (lowercase, digits, . _ - /)", source, rs.ID)
	}
	seen := map[string]bool{}
	for i, r := range rs.Rules {
		if !ruleIDPattern.MatchString(r.ID) {
			return nil, fmt.Errorf("rules: %s: rule %d: invalid id %q (lowercase, digits, . _ -)", source, i, r.ID)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: %s: duplicate rule id %q", source, r.ID)
		}
		seen[r.ID] = true
	}
	rs.dir = dir
	return &rs, nil
}

// IsDefault reports whether the ruleset is on by default.
func (rs *Ruleset) IsDefault() bool { return rs.Default == nil || *rs.Default }

// IsEnabled reports whether the rule is on within its ruleset by default.
func (s *Spec) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// FullID returns "<ruleset id>:<rule id>".
func FullID(set, rule string) string { return set + ":" + rule }

// State is the effective on/off state of one rule.
type State struct {
	Set  *Ruleset
	Spec *Spec
	On   bool
}

// Resolve applies a selection and returns every rule with its state, ordered
// by ruleset ID then file order.
func (c *Catalog) Resolve(sel Selection) ([]State, error) {
	setOverride := map[string]bool{}
	ruleOverride := map[string]bool{}
	apply := func(ids []string, on bool, field string) error {
		for _, id := range ids {
			setID, ruleID, isRule := strings.Cut(id, ":")
			rs, ok := c.Sets[setID]
			if !ok {
				return fmt.Errorf("rules: %s: unknown ruleset %q", field, setID)
			}
			if !isRule {
				setOverride[setID] = on
				continue
			}
			if !slicesContainsRule(rs, ruleID) {
				return fmt.Errorf("rules: %s: unknown rule %q in ruleset %q", field, ruleID, setID)
			}
			ruleOverride[id] = on
		}
		return nil
	}
	if err := apply(sel.Enable, true, "enable"); err != nil {
		return nil, err
	}
	// Disable wins over enable.
	if err := apply(sel.Disable, false, "disable"); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(c.Sets))
	for id := range c.Sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []State
	for _, id := range ids {
		rs := c.Sets[id]
		setOn := rs.IsDefault()
		if v, ok := setOverride[id]; ok {
			setOn = v
		}
		for i := range rs.Rules {
			spec := &rs.Rules[i]
			on := setOn && spec.IsEnabled()
			if v, ok := ruleOverride[FullID(id, spec.ID)]; ok {
				on = v
			}
			out = append(out, State{Set: rs, Spec: spec, On: on})
		}
	}
	return out, nil
}

func slicesContainsRule(rs *Ruleset, id string) bool {
	for _, r := range rs.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Compile resolves the selection and compiles every rule that is on.
func (c *Catalog) Compile(sel Selection) ([]detect.Rule, error) {
	states, err := c.Resolve(sel)
	if err != nil {
		return nil, err
	}
	var out []detect.Rule
	for _, st := range states {
		if !st.On {
			continue
		}
		r, err := compile(st.Set, st.Spec)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Default returns a detector with the built-in rulesets at their defaults.
func Default() (*detect.Detector, error) {
	c, err := Load(nil)
	if err != nil {
		return nil, err
	}
	compiled, err := c.Compile(Selection{})
	if err != nil {
		return nil, err
	}
	return detect.New(compiled), nil
}

func compile(rs *Ruleset, s *Spec) (detect.Rule, error) {
	id := FullID(rs.ID, s.ID)
	fail := func(format string, args ...any) (detect.Rule, error) {
		return detect.Rule{}, fmt.Errorf("rules: %s (%s): %s", id, rs.Source, fmt.Sprintf(format, args...))
	}
	if strings.TrimSpace(s.Kind) == "" {
		return fail("kind is required")
	}
	hasValues := len(s.Values) > 0 || s.ValuesFile != ""
	if (s.Pattern == "") == !hasValues {
		return fail("set exactly one of pattern or values / values_file")
	}

	r := detect.Rule{ID: id, Kind: s.Kind, Group: s.Group}
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fail("pattern: %v", err)
		}
		if s.Group < 0 || s.Group > re.NumSubexp() {
			return fail("group %d out of range (pattern has %d groups)", s.Group, re.NumSubexp())
		}
		r.Re = re
	} else {
		if s.Group != 0 {
			return fail("group is only valid with pattern")
		}
		values := append([]string(nil), s.Values...)
		if s.ValuesFile != "" {
			if rs.dir == "" {
				return fail("values_file is not supported in built-in rulesets")
			}
			fromFile, err := readLines(resolvePath(rs.dir, s.ValuesFile))
			if err != nil {
				return fail("values_file: %v", err)
			}
			values = append(values, fromFile...)
		}
		re, err := literalPattern(values, s.CaseInsensitive)
		if err != nil {
			return fail("%v", err)
		}
		r.Re = re
	}

	for _, a := range s.Allow {
		re, err := regexp.Compile(a)
		if err != nil {
			return fail("allow %q: %v", a, err)
		}
		r.Allow = append(r.Allow, re)
	}
	for _, name := range s.Validators {
		v, ok := Validators[name]
		if !ok {
			return fail("unknown validator %q (known: %s)", name, strings.Join(validatorNames(), ", "))
		}
		r.Validators = append(r.Validators, v)
	}
	return r, nil
}

func literalPattern(values []string, caseInsensitive bool) (*regexp.Regexp, error) {
	var parts []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			parts = append(parts, regexp.QuoteMeta(v))
		}
	}
	if len(parts) == 0 {
		return nil, errors.New("no values")
	}
	// Longest first so that "db.example" does not shadow "db.example.internal".
	sort.SliceStable(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	expr := "(?:" + strings.Join(parts, "|") + ")"
	if caseInsensitive {
		expr = "(?i)" + expr
	}
	return regexp.Compile(expr)
}

func readLines(p string) ([]string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func resolvePath(dir, p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[1:])
		}
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}
