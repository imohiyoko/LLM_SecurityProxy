package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/allow"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

// console is where `llmsp allow add` asks for confirmation.
type console struct {
	in  io.Reader
	out io.Writer
	tty bool // in is a terminal
}

func stdConsole() console {
	fi, err := os.Stdin.Stat()
	return console{in: os.Stdin, out: os.Stdout, tty: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

func allowCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: llmsp allow add|list|rm")
	}
	switch args[0] {
	case "add":
		return allowAdd(args[1:], stdConsole())
	case "list":
		return allowList(args[1:], os.Stdout)
	case "rm":
		return allowRm(args[1:], os.Stdout)
	}
	return fmt.Errorf("unknown allow command %q", args[0])
}

// checkProfile reports an error if profile is not one the config defines.
func checkProfile(cfg *config.Config, profile string) error {
	if profile == "" || profile == "default" {
		return nil
	}
	_, err := cfg.Masking(profile)
	return err
}

// allowAdd adds a stored value, or one given with -value, to allow.json
// after showing it and asking for confirmation on the terminal.
func allowAdd(args []string, c console) error {
	var value, profile string
	var force, yes bool
	e, err := load("allow add", args, func(fs *flag.FlagSet) {
		fs.StringVar(&value, "value", "", "the value itself, instead of a placeholder or ID")
		fs.StringVar(&profile, "profile", "", "only for this profile (default: every profile)")
		fs.BoolVar(&force, "force", false, "allow a value that a credential rule masked")
		fs.BoolVar(&yes, "yes", false, "do not ask; needed without a terminal (the proxy logs a warning)")
	})
	if err != nil {
		return err
	}
	if err := checkProfile(e.cfg, profile); err != nil {
		return err
	}
	if (value == "") == (e.flags.NArg() != 1) || e.flags.NArg() > 1 {
		return errors.New("usage: llmsp allow add [-profile P] [-force] [-yes] PLACEHOLDER|ID, or -value V")
	}

	// The stored record says how the value was masked; a value given with
	// -value may not be stored (redacted, or not seen yet).
	var rec store.Record
	var recs []store.Record
	found := false
	if dbExists(e.cfg.DataDir) {
		st, err := openStoreForReading(e.cfg.DataDir)
		if err != nil {
			return err
		}
		id := ""
		if value != "" {
			id = st.ID(value)
		} else if id, err = parseID(e.flags.Arg(0)); err != nil {
			st.Close()
			return err
		}
		recs, err = st.Records()
		st.Close()
		if err != nil {
			return err
		}
		if i := slices.IndexFunc(recs, func(r store.Record) bool { return r.ID == id }); i >= 0 {
			rec, found = recs[i], true
		}
	} else if value == "" {
		return fmt.Errorf("nothing masked yet: no store in %s; use -value", e.cfg.DataDir)
	}
	if value == "" {
		if !found {
			return fmt.Errorf("%s is not in the store (redacted values are never stored; use -value)", e.flags.Arg(0))
		}
		value = rec.Value
	}
	if !found {
		rec = store.Record{Value: value}
	}
	// What the rules of every profile the entry applies to would mask in
	// the value: a credential anywhere in it, for any of them, needs -force.
	matches, err := e.findInProfiles(profile, value)
	if err != nil {
		return err
	}
	view := newMaskedView(e.catalog, true, false, recs)
	secret := view.secret(rec)
	for _, m := range matches {
		r := store.Record{Kind: placeholder.NormalizeKind(m.Kind), Origin: store.Origin{Rule: m.Rule}}
		if !found && rec.Rule == "" && m.Start == 0 && m.End == len(value) {
			rec.Kind, rec.Rule = r.Kind, r.Rule // shown as the value's rule
		}
		if view.secret(r) {
			secret = true
			if rec.Rule == "" {
				rec.Kind, rec.Rule = r.Kind, r.Rule
			}
		}
	}
	if secret && !force {
		return fmt.Errorf("this value was masked by a credential rule (%s, %s); if you are sure it is not a secret, add -force", orDash(rec.Rule), orDash(rec.Kind))
	}
	path := allow.Path(e.cfg.DataDir)
	entries, err := allow.Load(path)
	if err != nil {
		return err
	}
	if allow.Index(entries, value, profile) >= 0 {
		fmt.Fprintln(c.out, "already allowed")
		return nil
	}

	// A credential's value is not printed, even with -force: an agent
	// running this command would read it in the output, after which it is
	// no longer masked.
	shown := strconv.Quote(value)
	if secret {
		shown = fmt.Sprintf("(credential, %d chars, not shown)", utf8.RuneCountInString(value))
	}
	scope := "every profile"
	if profile != "" {
		scope = "profile " + profile
	}
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "value\t%s\n", shown)
	fmt.Fprintf(w, "kind\t%s\n", orDash(rec.Kind))
	fmt.Fprintf(w, "rule\t%s\n", orDash(rec.Rule))
	fmt.Fprintf(w, "scope\t%s\n", scope)
	w.Flush()

	switch {
	case yes:
		fmt.Fprintln(c.out, "warning: added without confirmation (-yes); the proxy logs a warning for it")
	case !c.tty:
		return errors.New("no terminal to confirm on: run this in a terminal, or pass -yes")
	default:
		fmt.Fprint(c.out, "Never mask this value again? [y/N] ")
		line, _ := bufio.NewReader(c.in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(c.out, "not added")
			return nil
		}
	}
	// The file is read again under the lock: another llmsp allow may have
	// changed it while this one waited for confirmation.
	entry := allow.Entry{
		Value: value, Profile: profile, Kind: rec.Kind, Rule: rec.Rule,
		Added: time.Now().UTC().Truncate(time.Second), Unconfirmed: yes,
	}
	already := false
	if err := allow.Update(path, func(entries []allow.Entry) ([]allow.Entry, error) {
		if allow.Index(entries, value, profile) >= 0 {
			already = true
			return entries, nil
		}
		return append(entries, entry), nil
	}); err != nil {
		return err
	}
	if already {
		fmt.Fprintln(c.out, "already allowed")
		return nil
	}
	fmt.Fprintf(c.out, "added; a running proxy stops masking it within a second (%s)\n", path)
	return nil
}

// findInProfiles returns what the rules of profile would match in value; with
// no profile, what those of every configured profile and of the top level
// would, since such an entry applies to all of them.
func (e *env) findInProfiles(profile, value string) ([]detect.Match, error) {
	var eps []config.Endpoint
	if profile == "" || profile == "default" {
		base, err := e.cfg.Masking("")
		if err != nil {
			return nil, err
		}
		eps = append(eps, base)
	}
	if profile == "" {
		for name := range e.cfg.Profiles {
			eps = append(eps, e.cfg.Endpoint(name))
		}
	} else if profile != "default" {
		ep, err := e.cfg.Masking(profile)
		if err != nil {
			return nil, err
		}
		eps = append(eps, ep)
	}
	var out []detect.Match
	for _, ep := range eps {
		det, _, err := e.masking(ep)
		if err != nil {
			return nil, err
		}
		out = append(out, det.Find(value)...)
	}
	return out, nil
}

// parseID takes a placeholder or a bare ID.
func parseID(arg string) (string, error) {
	if m := placeholder.Pattern.FindStringSubmatch(arg); m != nil {
		return m[2], nil
	}
	if idPattern.MatchString(arg) {
		return arg, nil
	}
	return "", fmt.Errorf("%q is neither a placeholder (__LLMSP_KIND_0123456789ab__) nor an ID", arg)
}

func dbExists(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, "llmsp.db"))
	return err == nil
}

// allowList prints the entries, numbered for `llmsp allow rm`.
func allowList(args []string, out io.Writer) error {
	e, err := load("allow list", args, nil)
	if err != nil {
		return err
	}
	entries, err := allow.Load(allow.Path(e.cfg.DataDir))
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no values allowed")
		return nil
	}
	var recs []store.Record
	if dbExists(e.cfg.DataDir) {
		st, err := openStoreForReading(e.cfg.DataDir)
		if err != nil {
			return err
		}
		recs, err = st.Records()
		st.Close()
		if err != nil {
			return err
		}
	}
	view := newMaskedView(e.catalog, true, false, recs)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "#\tPROFILE\tKIND\tRULE\tADDED\tVALUE")
	for i, en := range entries {
		added := en.Added.Local().Format("2006-01-02 15:04")
		if en.Unconfirmed {
			added += " (-yes)"
		}
		// A credential added with -force is not printed: see allowAdd.
		v := view.value(store.Record{Kind: en.Kind, Origin: store.Origin{Rule: en.Rule}, Value: en.Value}, true, 0)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", i+1, orDash(en.Profile), orDash(en.Kind), orDash(en.Rule), added, v)
	}
	return w.Flush()
}

// allowRm removes an entry by its number in `llmsp allow list`, or by value.
func allowRm(args []string, out io.Writer) error {
	var value, profile string
	e, err := load("allow rm", args, func(fs *flag.FlagSet) {
		fs.StringVar(&value, "value", "", "the value to remove")
		fs.StringVar(&profile, "profile", "", "with -value: the entry for this profile")
	})
	if err != nil {
		return err
	}
	n := 0
	switch {
	case value != "" && e.flags.NArg() == 0:
	case value == "" && e.flags.NArg() == 1:
		if n, err = strconv.Atoi(e.flags.Arg(0)); err != nil || n < 1 {
			return fmt.Errorf("%q: want a number from `llmsp allow list`", e.flags.Arg(0))
		}
	default:
		return errors.New("usage: llmsp allow rm N, or -value V [-profile P]")
	}
	// Under the lock, on the entries as they are now. The value is not
	// printed: it may be a credential added with -force.
	if err := allow.Update(allow.Path(e.cfg.DataDir), func(entries []allow.Entry) ([]allow.Entry, error) {
		i := n - 1
		if value != "" {
			if i = allow.Index(entries, value, profile); i < 0 {
				return nil, errors.New("no such entry")
			}
		} else if i >= len(entries) {
			return nil, fmt.Errorf("no entry %d: `llmsp allow list` shows %d", n, len(entries))
		}
		return slices.Delete(entries, i, i+1), nil
	}); err != nil {
		return err
	}
	fmt.Fprintln(out, "removed; a running proxy masks the value again within a second")
	return nil
}
