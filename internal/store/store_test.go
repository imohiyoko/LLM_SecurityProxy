package store

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPutResolvePersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id1, kind, err := s.Put("email", "alice@corp.dev")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "EMAIL" || len(id1) != 12 {
		t.Fatalf("kind %q id %q", kind, id1)
	}
	id2, kind2, _ := s.Put("known", "alice@corp.dev")
	if id1 != id2 || kind2 != "EMAIL" {
		t.Fatalf("not deterministic: %s/%s %s", id1, id2, kind2)
	}
	if v, ok := s.Resolve(id1); !ok || v != "alice@corp.dev" {
		t.Fatalf("resolve: %q %v", v, ok)
	}
	s.Close()

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file perms: %v %v", info.Mode(), err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, ok := s2.Resolve(id1); !ok || v != "alice@corp.dev" {
		t.Fatalf("after reopen: %q %v", v, ok)
	}
	if s2.ID("alice@corp.dev") != id1 {
		t.Fatal("id changed after reopen")
	}
	known, _ := s2.Known()
	if len(known) != 1 {
		t.Fatalf("known: %v", known)
	}
}

func TestValuesEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put("x", "plaintext-marker-value"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, name := range []string{"llmsp.db", "llmsp.db-wal"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "plaintext-marker-value") {
			t.Fatalf("%s contains plaintext", name)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("x", "value-123456")
	s.Close()
	if err := os.WriteFile(filepath.Join(dir, keyFile), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

// Two stores on one directory stand for two llmsp processes, one per
// profile: a value one of them stores is known to the other within
// syncEvery, without a restart.
func TestKnownSeesOtherProcess(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if _, _, err := a.Put("NAME", "Jane Example-Doe"); err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		known, _ := b.Known()
		return slices.Contains(known, "Jane Example-Doe")
	}
	deadline := time.Now().Add(syncEvery + 2*time.Second)
	for !has() {
		if time.Now().After(deadline) {
			t.Fatal("value stored by another process never became known")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v, ok := b.Resolve(a.ID("Jane Example-Doe")); !ok || v != "Jane Example-Doe" {
		t.Errorf("Resolve = %q, %v", v, ok)
	}
}

// Processes starting at once on an empty directory agree on one key.
func TestConcurrentKeyCreation(t *testing.T) {
	for range 20 {
		dir := t.TempDir()
		path := filepath.Join(dir, keyFile)
		var wg sync.WaitGroup
		keys := make([][]byte, 8)
		errs := make([]error, 8)
		for i := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				keys[i], errs[i] = loadOrCreateKey(path)
			}()
		}
		wg.Wait()
		for i := range keys {
			if errs[i] != nil {
				t.Fatalf("loadOrCreateKey: %v", errs[i])
			}
			if string(keys[i]) != string(keys[0]) {
				t.Fatal("processes created different keys")
			}
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("left behind: %v", entries)
		}
	}
}

func TestCheckWrites(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if known, _ := s.Known(); len(known) != 0 {
		t.Errorf("Check stored a value: %v", known)
	}
	s.Close()
	if err := s.Check(t.Context()); err == nil {
		t.Error("Check on a closed store succeeded")
	}
}

// A row another process wrote that cannot be decrypted does not hide the
// good rows read before it, does not crash, and is reported by Check.
func TestSyncBadRowKeepsGoodRows(t *testing.T) {
	for name, nonce := range map[string]string{"wrong ciphertext": "x'000000000000000000000000'", "short nonce": "x'00'"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			a, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()

			if _, _, err := a.Put("NAME", "Jane Example-Doe"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.db.Exec(`INSERT INTO secrets (id, kind, nonce, ciphertext, created_at) VALUES ('0123456789ab', 'X', ` + nonce + `, x'00', 0)`); err != nil {
				t.Fatal(err)
			}
			time.Sleep(syncEvery + 100*time.Millisecond)
			if known, _ := b.Known(); !slices.Contains(known, "Jane Example-Doe") {
				t.Errorf("good row before the bad one not masked: %v", known)
			}
			if err := b.Check(t.Context()); err == nil || !strings.Contains(err.Error(), "other processes") {
				t.Errorf("Check = %v, want the sync error", err)
			}
		})
	}
}
