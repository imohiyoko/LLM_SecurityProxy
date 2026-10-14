package relax

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func limit(name string) (time.Duration, bool) {
	if name == "loose" {
		return 2 * time.Hour, true
	}
	return 0, false
}

func TestValid(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		s    State
		want bool
	}{
		"in effect":           {State{"loose", now.Add(-time.Hour), now.Add(time.Hour)}, true},
		"expired":             {State{"loose", now.Add(-2 * time.Hour), now}, false},
		"longer than allowed": {State{"loose", now.Add(-time.Minute), now.Add(3 * time.Hour)}, false},
		"not started":         {State{"loose", now.Add(time.Minute), now.Add(time.Hour)}, false},
		"not relaxable":       {State{"strict", now.Add(-time.Minute), now.Add(time.Hour)}, false},
	} {
		if got := Valid(tc.s, now, limit); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	w := &Watcher{Path: path, Limit: limit}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if _, ok := w.Active(now); ok {
		t.Fatal("no file: want no relaxation")
	}
	if err := Save(path, State{"loose", now, now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.Active(now.Add(100 * time.Millisecond)); ok {
		t.Error("read at most once a second: the new file is not seen yet")
	}
	if s, ok := w.Active(now.Add(time.Second)); !ok || s.Profile != "loose" {
		t.Errorf("got %+v %v, want loose", s, ok)
	}
	// Expiry needs no new read.
	if _, ok := w.Active(now.Add(time.Hour)); ok {
		t.Error("expired: want no relaxation")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotErr error
	w.Changed = func(_ State, _ bool, err error) { gotErr = err }
	if _, ok := w.Active(now.Add(2 * time.Second)); ok || gotErr == nil {
		t.Errorf("unreadable file: want no relaxation and an error, got ok=%v err=%v", ok, gotErr)
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if err := Clear(path); err != nil {
		t.Errorf("clearing twice: %v", err)
	}
}
