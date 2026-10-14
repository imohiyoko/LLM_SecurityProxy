// Package relax keeps the one temporary relaxation in effect: for a while,
// requests routed to stricter profiles are served by a looser one instead.
//
// The state is a small file in the data directory, written by `llmsp relax`
// and read by the running proxy. The proxy checks the expiry on every
// request, so a relaxation ends on time whatever else happens.
package relax

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileName is the state file in the data directory.
const FileName = "relax.json"

// State is a relaxation: Profile serves requests until Until.
type State struct {
	Profile string    `json:"profile"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
}

// Path is the state file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

// Load reads the state; no file is no relaxation (ok false).
func Load(path string) (State, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, false, fmt.Errorf("%s: %w", path, err)
	}
	return s, true, nil
}

// Save replaces the state.
func Save(path string, s State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clear ends any relaxation.
func Clear(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Limit is how long a profile may be relaxed to.
type Limit func(profile string) (max time.Duration, ok bool)

// Valid reports whether s is in effect at now: not expired, for a profile
// that may be relaxed to, and no longer than that profile allows (the file
// is checked again here, not only when it is written).
func Valid(s State, now time.Time, limit Limit) bool {
	max, ok := limit(s.Profile)
	return ok && now.Before(s.Until) && !now.Before(s.Since) && s.Until.Sub(s.Since) <= max
}

// checkEvery bounds how often the proxy reads the state file.
const checkEvery = time.Second

// Watcher tells the proxy which relaxation is in effect.
type Watcher struct {
	Path  string
	Limit Limit
	// Changed, if set, is called when the relaxation in effect changes:
	// with the new state, or ok false when it ended.
	Changed func(s State, ok bool, err error)

	mu      sync.Mutex
	checked time.Time
	state   State
	ok      bool
	err     error
}

// Active returns the relaxation in effect at now. A state file that cannot
// be read counts as no relaxation: the strict profiles stay in force.
func (w *Watcher) Active(now time.Time) (State, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.checked.IsZero() || now.Sub(w.checked) >= checkEvery || now.Before(w.checked) {
		w.checked = now
		s, ok, err := Load(w.Path)
		ok = ok && err == nil
		if ok != w.ok || s != w.state || (err == nil) != (w.err == nil) {
			if w.Changed != nil {
				w.Changed(s, ok, err)
			}
		}
		w.state, w.ok, w.err = s, ok, err
	}
	if w.ok && Valid(w.state, now, w.Limit) {
		return w.state, true
	}
	return State{}, false
}
