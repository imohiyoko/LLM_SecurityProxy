// Package store keeps the mapping from placeholder ID to the original value.
//
// Values are encrypted at rest with AES-256-GCM. IDs are an HMAC of the value,
// so the same value always gets the same placeholder (stable history, stable
// prompt cache) and the ID reveals nothing about the value.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"

	_ "modernc.org/sqlite"
)

const keyFile = "master.key"

// Store is safe for concurrent use.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	mac  []byte

	mu      sync.RWMutex
	values  map[string]entry // id -> entry
	known   []string         // values, longest first
	version uint64           // bumped whenever known changes
}

type entry struct {
	kind, value string
}

// Open opens (or creates) the key and database in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	master, err := loadOrCreateKey(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	encKey, err := hkdf.Key(sha256.New, master, nil, "llmsp/enc/v1", 32)
	if err != nil {
		return nil, err
	}
	macKey, err := hkdf.Key(sha256.New, master, nil, "llmsp/id/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dir, "llmsp.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id         TEXT PRIMARY KEY,
		kind       TEXT NOT NULL,
		nonce      BLOB NOT NULL,
		ciphertext BLOB NOT NULL,
		created_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(dbPath, 0o600)

	s := &Store{db: db, aead: aead, mac: macKey, values: map[string]entry{}}
	if err := s.load(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func loadOrCreateKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("store: %s must be 32 bytes, got %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return nil, err
	}
	return b, f.Sync()
}

func (s *Store) load() error {
	rows, err := s.db.Query(`SELECT id, kind, nonce, ciphertext FROM secrets`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind string
		var nonce, ct []byte
		if err := rows.Scan(&id, &kind, &nonce, &ct); err != nil {
			return err
		}
		pt, err := s.aead.Open(nil, nonce, ct, []byte(id))
		if err != nil {
			return fmt.Errorf("store: decrypt %s: %w (wrong master.key?)", id, err)
		}
		s.values[id] = entry{kind: kind, value: string(pt)}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.rebuildKnown()
	return nil
}

// ID returns the deterministic placeholder ID for value.
func (s *Store) ID(value string) string {
	m := hmac.New(sha256.New, s.mac)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:placeholder.IDLen]
}

// Put records value and returns its ID and the kind it was first stored under.
func (s *Store) Put(kind, value string) (id, storedKind string, err error) {
	id = s.ID(value)
	kind = placeholder.NormalizeKind(kind)

	s.mu.RLock()
	e, ok := s.values[id]
	s.mu.RUnlock()
	if ok {
		if e.value != value {
			return "", "", fmt.Errorf("store: id collision on %s", id)
		}
		return id, e.kind, nil
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	ct := s.aead.Seal(nil, nonce, []byte(value), []byte(id))

	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.values[id]; ok { // raced with another Put
		return id, e.kind, nil
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO secrets (id, kind, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, kind, nonce, ct, time.Now().Unix()); err != nil {
		return "", "", err
	}
	s.values[id] = entry{kind: kind, value: value}
	s.rebuildKnown()
	return id, kind, nil
}

// Resolve returns the original value for id.
func (s *Store) Resolve(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.values[id]
	return e.value, ok
}

// Kind returns the kind id was first stored under.
func (s *Store) Kind(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.values[id]
	return e.kind, ok
}

// Known returns every stored value, longest first, and a version that changes
// whenever the set changes. The slice must not be modified.
func (s *Store) Known() ([]string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.known, s.version
}

// rebuildKnown must be called with mu held for writing (or during Open).
func (s *Store) rebuildKnown() {
	known := make([]string, 0, len(s.values))
	for _, e := range s.values {
		known = append(known, e.value)
	}
	sort.Slice(known, func(i, j int) bool {
		if len(known[i]) != len(known[j]) {
			return len(known[i]) > len(known[j])
		}
		return known[i] < known[j]
	})
	s.known = known
	s.version++
}
