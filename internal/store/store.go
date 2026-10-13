// Package store keeps the mapping from placeholder ID to the original value.
//
// Values are encrypted at rest with AES-256-GCM. IDs are an HMAC of the value,
// so the same value always gets the same placeholder (stable history, stable
// prompt cache) and the ID reveals nothing about the value.
package store

import (
	"context"
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
	"sync/atomic"
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
	lastRow int64            // highest rowid read from the database

	// Another process on the same data directory (one llmsp per profile)
	// adds values too; they are read at most once per syncEvery.
	syncMu   sync.Mutex
	lastSync atomic.Int64 // unix nanoseconds
	syncErr  error        // last sync's error; mu guards it
}

// syncEvery bounds how long a value stored by another process can go
// unrecognised here.
const syncEvery = time.Second

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
	);
	CREATE TABLE IF NOT EXISTS health (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		at INTEGER NOT NULL
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
	if errors.Is(err, os.ErrNotExist) {
		b, err = createKey(path)
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("store: %s must be 32 bytes, got %d", path, len(b))
	}
	return b, nil
}

// createKey writes a new key to path, unless another process got there
// first: then that key is returned. The key is written to a temporary file
// and linked into place, so no reader ever sees a partial file.
func createKey(path string) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), keyFile+".tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err != nil {
		return nil, err
	}
	err = os.Link(tmp, path)
	switch {
	case errors.Is(err, os.ErrExist):
		return os.ReadFile(path)
	case err != nil:
		// No hard links (exFAT, some network mounts): create the file
		// exclusively instead. A process that starts at the same moment
		// may then see EEXIST or a partial key and fail; restarting fixes it.
		return b, writeExclusive(path, b)
	}
	return b, nil
}

func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// load reads the rows added since the last load, by this or another process.
// Rows are never deleted, so rowids only grow. mu must be held for writing
// (or Open be running).
func (s *Store) load() error {
	rows, err := s.db.Query(`SELECT rowid, id, kind, nonce, ciphertext FROM secrets WHERE rowid > ? ORDER BY rowid`, s.lastRow)
	if err != nil {
		return err
	}
	defer rows.Close()
	// Values read before a failure are in s.values, where Resolve finds
	// them; they must be in known too, or they would not be masked.
	added := false
	defer func() {
		if added || s.version == 0 {
			s.rebuildKnown()
		}
	}()
	for rows.Next() {
		var row int64
		var id, kind string
		var nonce, ct []byte
		if err := rows.Scan(&row, &id, &kind, &nonce, &ct); err != nil {
			return err
		}
		s.lastRow = row
		if _, ok := s.values[id]; ok {
			continue
		}
		if len(nonce) != s.aead.NonceSize() { // Open would panic
			return fmt.Errorf("store: decrypt %s: bad nonce length %d", id, len(nonce))
		}
		pt, err := s.aead.Open(nil, nonce, ct, []byte(id))
		if err != nil {
			return fmt.Errorf("store: decrypt %s: %w (wrong master.key?)", id, err)
		}
		s.values[id] = entry{kind: kind, value: string(pt)}
		added = true
	}
	return rows.Err()
}

// sync loads values stored by other processes, at most once per syncEvery.
// An error keeps the values already loaded and is reported by Check until a
// sync succeeds.
func (s *Store) sync() {
	now := time.Now().UnixNano()
	if now-s.lastSync.Load() < int64(syncEvery) || !s.syncMu.TryLock() {
		return
	}
	defer s.syncMu.Unlock()
	s.lastSync.Store(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncErr = s.load()
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

// Check reports whether the database can still be written: a full disk or a
// write lock held too long by another process fails it, where a read would
// still succeed. It writes one fixed row, never a value.
//
// It also reports a failure to load values stored by other processes: until
// that succeeds, those values are not masked here.
func (s *Store) Check(ctx context.Context) error {
	s.mu.RLock()
	serr := s.syncErr
	s.mu.RUnlock()
	if serr != nil {
		return fmt.Errorf("loading values from other processes: %w", serr)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO health (id, at) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET at = excluded.at`, time.Now().Unix())
	return err
}

// Known returns every stored value, longest first, and a version that changes
// whenever the set changes. The slice must not be modified. Values stored by
// another process on the same database are included within syncEvery.
func (s *Store) Known() ([]string, uint64) {
	s.sync()
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
