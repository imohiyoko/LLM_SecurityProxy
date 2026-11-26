package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/allow"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

// secretRulesets hold rules whose matches are credentials: their values are
// not printed unless -show-secrets is given.
var secretRulesets = []string{"builtin/credentials", "builtin/generic"}

// maskedView decides how much of a stored value `llmsp masked` prints.
type maskedView struct {
	show, showSecrets bool
	// secretKinds are the kinds of the rules in secretRulesets, for values
	// stored before the rule was recorded.
	secretKinds map[string]bool
	// byValue holds the stored records, to find the value a KNOWN record
	// without a rule (a JSON-escaped form stored by an older llmsp) is the
	// escaped form of.
	byValue map[string]store.Record
}

func newMaskedView(c *rules.Catalog, show, showSecrets bool, recs []store.Record) maskedView {
	v := maskedView{show: show, showSecrets: showSecrets, secretKinds: map[string]bool{}, byValue: map[string]store.Record{}}
	for _, r := range recs {
		v.byValue[r.Value] = r
	}
	// The built-in kinds count even when a user ruleset replaces one of
	// these sets: old rows were masked by whatever rules were in use then.
	catalogs := []*rules.Catalog{c}
	if builtin, err := rules.Load(nil); err == nil {
		catalogs = append(catalogs, builtin)
	}
	for _, c := range catalogs {
		for _, id := range secretRulesets {
			if set, ok := c.Sets[id]; ok {
				for _, spec := range set.Rules {
					v.secretKinds[placeholder.NormalizeKind(spec.Kind)] = true
				}
			}
		}
	}
	return v
}

// secret reports whether r was masked as a credential.
func (v maskedView) secret(r store.Record) bool {
	if r.Rule == mask.ForeignPlaceholderRule {
		return true
	}
	if r.Rule == "" && r.Kind == "KNOWN" {
		// An escaped form stored before kinds and rules were carried
		// over: it is a secret if the value it stands for is one, and is
		// hidden if that value cannot be found.
		if u, ok := jsonUnescape(r.Value); ok && u != r.Value {
			if o, ok := v.byValue[u]; ok && o.Kind != "KNOWN" {
				return v.secret(o)
			}
		}
		return true
	}
	if r.Rule == "" {
		return v.secretKinds[r.Kind]
	}
	set, _, _ := strings.Cut(r.Rule, ":")
	return slices.Contains(secretRulesets, set)
}

// value renders r's value: hidden for a credential unless showSecrets, in
// full (up to limit runes; 0 for no limit) with show, otherwise only its
// first few characters, enough to recognise a value you are looking for.
func (v maskedView) value(r store.Record, full bool, limit int) string {
	n := utf8.RuneCountInString(r.Value)
	if v.secret(r) && !v.showSecrets {
		return fmt.Sprintf("(hidden: credential, %d chars; -show-secrets to print)", n)
	}
	if full {
		if limit > 0 && n > limit {
			return strconv.Quote(string([]rune(r.Value)[:limit])) + fmt.Sprintf("… (%d chars)", n)
		}
		return strconv.Quote(r.Value)
	}
	keep := min(3, n/3)
	return strconv.Quote(string([]rune(r.Value)[:keep])) + fmt.Sprintf("… (%d chars)", n)
}

// jsonUnescape decodes v as the inside of a JSON string literal.
func jsonUnescape(v string) (string, bool) {
	var u string
	if err := json.Unmarshal([]byte(`"`+v+`"`), &u); err != nil {
		return "", false
	}
	return u, true
}

// openStoreForReading opens the data directory's store, refusing to create
// one: inspecting must not make a new key.
func openStoreForReading(dataDir string) (*store.Store, error) {
	for _, f := range []string{"master.key", "llmsp.db"} {
		if _, err := os.Stat(filepath.Join(dataDir, f)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("nothing masked yet: no %s in %s", f, dataDir)
			}
			return nil, err
		}
	}
	return store.Open(dataDir)
}

func maskedCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: llmsp masked list|show")
	}
	switch args[0] {
	case "list":
		return maskedList(args[1:], os.Stdout)
	case "show":
		return maskedShow(args[1:], os.Stdout)
	}
	return fmt.Errorf("unknown masked command %q", args[0])
}

// maskedList prints stored values, newest first.
func maskedList(args []string, out io.Writer) error {
	var since, kind, rule, profile, grep string
	var show, showSecrets bool
	var limit int
	e, err := load("masked list", args, func(fs *flag.FlagSet) {
		fs.StringVar(&since, "since", "", "only values first masked within this long, e.g. 30m, 2h, 7d")
		fs.StringVar(&kind, "kind", "", "only this kind, e.g. EMAIL")
		fs.StringVar(&rule, "rule", "", "only this rule or ruleset, e.g. builtin/pii:name or builtin/pii")
		fs.StringVar(&profile, "profile", "", "only values first masked for this profile")
		fs.StringVar(&grep, "grep", "", "only values containing this text (case-insensitive)")
		fs.BoolVar(&show, "show", false, "print values in full (credentials stay hidden)")
		fs.BoolVar(&showSecrets, "show-secrets", false, "also print values of credential rules")
		fs.IntVar(&limit, "n", 50, "print at most this many (0: all)")
	})
	if err != nil {
		return err
	}
	if e.flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", e.flags.Arg(0))
	}
	var after time.Time
	if since != "" {
		d, err := parseSince(since)
		if err != nil {
			return err
		}
		after = time.Now().Add(-d)
	}
	st, err := openStoreForReading(e.cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	recs, err := st.Records()
	if err != nil {
		return err
	}
	if kind != "" {
		kind = placeholder.NormalizeKind(kind)
	}
	grep = strings.ToLower(grep)
	var sel []store.Record
	for _, r := range slices.Backward(recs) {
		switch {
		case !after.IsZero() && r.Created.Before(after),
			kind != "" && r.Kind != kind,
			rule != "" && r.Rule != rule && !strings.HasPrefix(r.Rule, rule+":"),
			profile != "" && r.Profile != profile,
			grep != "" && !strings.Contains(strings.ToLower(r.Value), grep):
			continue
		}
		sel = append(sel, r)
	}
	shown := sel
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	allowed, err := allow.Load(allow.Path(e.cfg.DataDir))
	if err != nil {
		return err
	}
	view := newMaskedView(e.catalog, show, showSecrets, recs)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PLACEHOLDER\tRULE\tPROFILE\tFIRST MASKED\tVALUE")
	for _, r := range shown {
		v := view.value(r, show, 80)
		if slices.ContainsFunc(allowed, func(a allow.Entry) bool { return a.Value == r.Value }) {
			v += "  [allowed]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", placeholder.Format(r.Kind, r.ID), orDash(r.Rule),
			orDash(r.Profile), r.Created.Local().Format("2006-01-02 15:04"), v)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(shown) < len(sel) {
		fmt.Fprintf(out, "(%d of %d shown; -n 0 for all)\n", len(shown), len(sel))
	}
	return nil
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// maskedShow prints one stored value, given its placeholder or ID.
func maskedShow(args []string, out io.Writer) error {
	var showSecrets bool
	e, err := load("masked show", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&showSecrets, "show-secrets", false, "print the value even if a credential rule masked it")
	})
	if err != nil {
		return err
	}
	if e.flags.NArg() != 1 {
		return errors.New("usage: llmsp masked show [-show-secrets] PLACEHOLDER|ID")
	}
	arg := e.flags.Arg(0)
	id := arg
	if m := placeholder.Pattern.FindStringSubmatch(arg); m != nil {
		id = m[2]
	} else if !idPattern.MatchString(arg) {
		return fmt.Errorf("%q is neither a placeholder (__LLMSP_KIND_0123456789ab__) nor an ID", arg)
	}
	st, err := openStoreForReading(e.cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	recs, err := st.Records()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(recs, func(r store.Record) bool { return r.ID == id })
	if i < 0 {
		return fmt.Errorf("%s is not in the store (redacted values are never stored)", id)
	}
	r := recs[i]
	view := newMaskedView(e.catalog, true, showSecrets, recs)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "placeholder\t%s\n", placeholder.Format(r.Kind, r.ID))
	fmt.Fprintf(w, "kind\t%s\n", r.Kind)
	fmt.Fprintf(w, "rule\t%s\n", orDash(r.Rule))
	fmt.Fprintf(w, "profile\t%s\n", orDash(r.Profile))
	fmt.Fprintf(w, "first masked\t%s\n", r.Created.Local().Format(time.DateTime))
	fmt.Fprintf(w, "value\t%s\n", view.value(r, true, 0))
	return w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseSince is time.ParseDuration, plus a whole number of days ("7d").
func parseSince(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if d, err := strconv.Atoi(n); err == nil && d >= 0 {
			return time.Duration(d) * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("-since %q: want a duration such as 30m, 2h or 7d", s)
	}
	return d, nil
}
