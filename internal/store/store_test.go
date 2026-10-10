package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
