package allow

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	if es, err := Load(p); err != nil || es != nil {
		t.Fatalf("missing file: %v %v", es, err)
	}
	in := []Entry{{Value: "Status", Kind: "NAME", Rule: "builtin/pii:name", Added: time.Unix(1, 0).UTC()},
		{Value: "x@y.dev", Profile: "codex", Unconfirmed: true}}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm: %v %v", fi, err)
	}
	out, err := Load(p)
	if err != nil || len(out) != 2 || out[0] != in[0] || out[1] != in[1] {
		t.Fatalf("load: %+v %v", out, err)
	}
	if Index(out, "x@y.dev", "codex") != 1 || Index(out, "x@y.dev", "") != -1 {
		t.Fatal("index")
	}
	if err := os.WriteFile(p, []byte(`{"entries":[{"value":""}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("empty value accepted")
	}
}

func TestWatcher(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	var changes int
	w := &Watcher{Path: p, Every: time.Nanosecond, Changed: func([]Entry, error) { changes++ }}
	v0 := w.Version()
	if w.Allowed("", "Status") || changes != 0 {
		t.Fatalf("no file: allowed, or %d changes", changes)
	}
	if err := Save(p, []Entry{{Value: "Status"}, {Value: "only-codex", Profile: "codex"}}); err != nil {
		t.Fatal(err)
	}
	v1 := w.Version()
	if v1 == v0 || changes != 1 {
		t.Fatalf("not reloaded: %d %d, %d changes", v0, v1, changes)
	}
	if !w.Allowed("claude", "Status") || !w.Allowed("codex", "only-codex") || w.Allowed("claude", "only-codex") || w.Allowed("", "Statu") {
		t.Fatal("allowed")
	}
	if w.Version() != v1 {
		t.Fatal("version changed without a change")
	}
	// A broken file allows nothing.
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w.Version() == v1 || w.Allowed("claude", "Status") {
		t.Fatal("broken file still allows")
	}
	// Removed: nothing.
	Save(p, []Entry{{Value: "Status"}})
	w.Version()
	os.Remove(p)
	w.Version()
	if w.Allowed("", "Status") {
		t.Fatal("removed file still allows")
	}
}

// The file is looked at no more often than Every.
func TestWatcherThrottled(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	w := &Watcher{Path: p, Every: time.Hour}
	w.Version()
	Save(p, []Entry{{Value: "Status"}})
	w.Version()
	if w.Allowed("", "Status") {
		t.Fatal("read again within Every")
	}
}

// Concurrent updates are applied one after the other: none is lost.
func TestUpdateSerialized(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Update(p, func(es []Entry) ([]Entry, error) {
				return append(es, Entry{Value: fmt.Sprint("v", i)}), nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	es, err := Load(p)
	if err != nil || len(es) != 20 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
	if _, err := os.Stat(p + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock left: %v", err)
	}
	// A change that fails leaves the file as it was.
	if err := Update(p, func([]Entry) ([]Entry, error) { return nil, fmt.Errorf("no") }); err == nil {
		t.Fatal("error lost")
	}
	if es, _ := Load(p); len(es) != 20 {
		t.Fatalf("changed by a failed update: %d", len(es))
	}
}

// A mode change alone makes the watcher read the file again.
func TestWatcherModeChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	Save(p, []Entry{{Value: "Status"}})
	w := &Watcher{Path: p, Every: time.Nanosecond}
	w.Version()
	before := w.stamp
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	w.Version()
	if w.stamp == before {
		t.Fatal("mode change not noticed")
	}
}
