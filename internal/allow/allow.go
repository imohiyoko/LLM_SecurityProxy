// Package allow keeps the values the user has told llmsp never to mask,
// matched exactly. `llmsp allow add` writes them to a small file in the data
// directory, and the running proxy reads it within a second.
//
// The values are stored in plain text: the user decided they are not
// secret, and must be able to review them.
package allow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// FileName is the file in the data directory.
const FileName = "allow.json"

// Path is the file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

// Entry is one value never to mask.
type Entry struct {
	Value string `json:"value"`
	// Profile limits the entry to one profile; empty is every profile.
	Profile string `json:"profile,omitempty"`
	// Kind and Rule say how the value was masked when it was added, for
	// review only.
	Kind  string    `json:"kind,omitempty"`
	Rule  string    `json:"rule,omitempty"`
	Added time.Time `json:"added"`
	// Unconfirmed: added with -yes, without a terminal to confirm on. The
	// proxy logs a warning for such entries.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
}

type file struct {
	Entries []Entry `json:"entries"`
}

// Load reads the entries; no file is no entries.
func Load(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, e := range f.Entries {
		if e.Value == "" {
			return nil, fmt.Errorf("%s: entry %d has no value", path, i+1)
		}
	}
	return f.Entries, nil
}

// Save replaces the entries, through a temporary file of its own in the
// same directory, so a reader never sees a partial file.
func Save(path string, entries []Entry) error {
	b, err := json.MarshalIndent(file{Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// lockWait bounds how long Update waits for another one.
const lockWait = 10 * time.Second

// Update changes the entries with change, holding an OS lock on a file next
// to path so that concurrent updates (two `llmsp allow` commands) are applied
// one after the other, each to the entries as the previous one left them.
// The OS releases the lock when its holder exits, however it exits, so a
// lock is never taken over from a live holder. The lock file itself stays.
func Update(path string, change func([]Entry) ([]Entry, error)) error {
	lock := path + ".lock"
	f, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	deadline := time.Now().Add(lockWait)
	for {
		busy, err := tryLock(f)
		if err != nil {
			return fmt.Errorf("lock %s: %w", lock, err)
		}
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s is held by another llmsp allow", lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer unlock(f)
	entries, err := Load(path)
	if err != nil {
		return err
	}
	entries, err = change(entries)
	if err != nil {
		return err
	}
	return Save(path, entries)
}

// Covers reports whether e applies to profile.
func (e Entry) Covers(profile string) bool { return e.Profile == "" || e.Profile == profile }

// Index returns the entry for value and profile, or -1.
func Index(entries []Entry, value, profile string) int {
	return slices.IndexFunc(entries, func(e Entry) bool { return e.Value == value && e.Profile == profile })
}

// checkEvery bounds how often the proxy looks at the file by default.
const checkEvery = time.Second

// Watcher tells the proxy which values are allowed. It is safe for
// concurrent use.
type Watcher struct {
	Path string
	// Changed, if set, is called when the entries change, with the new
	// entries or the error reading them.
	Changed func(entries []Entry, err error)
	// Every is how often the file is looked at; 0 is once a second.
	Every time.Duration

	mu      sync.Mutex
	checked time.Time
	stamp   stamp
	values  map[string][]string // value -> profiles ("" for every one)
	version uint64
}

type stamp struct {
	mod   time.Time
	size  int64
	mode  os.FileMode // a chmod that makes the file unreadable changes no other field
	err   bool
	exist bool
}

// refresh reads the file if it may have changed. mu must be held.
func (w *Watcher) refresh(now time.Time) {
	every := w.Every
	if every == 0 {
		every = checkEvery
	}
	if !w.checked.IsZero() && now.Sub(w.checked) < every && !now.Before(w.checked) {
		return
	}
	w.checked = now
	var st stamp
	if fi, err := os.Stat(w.Path); err == nil {
		st = stamp{mod: fi.ModTime(), size: fi.Size(), mode: fi.Mode(), exist: true}
	} else if !errors.Is(err, os.ErrNotExist) {
		st.err = true
	}
	if st == w.stamp && w.version > 0 {
		return
	}
	w.stamp = st
	entries, err := Load(w.Path)
	// A file that cannot be read allows nothing: values are masked as if
	// it did not exist.
	values := map[string][]string{}
	if err == nil {
		for _, e := range entries {
			values[e.Value] = append(values[e.Value], e.Profile)
		}
	}
	changed := w.version == 0 || err != nil || !equal(values, w.values)
	w.values = values
	if changed {
		w.version++
		if w.Changed != nil && (w.version > 1 || len(entries) > 0 || err != nil) {
			w.Changed(entries, err)
		}
	}
}

func equal(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// Version changes whenever the allowed values do, so results computed
// with earlier ones can be discarded.
func (w *Watcher) Version() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refresh(time.Now())
	return w.version
}

// Allowed reports whether value is never to be masked for profile. It uses
// the values read by the last Version call.
func (w *Watcher) Allowed(profile, value string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.values[value] {
		if p == "" || p == profile {
			return true
		}
	}
	return false
}
