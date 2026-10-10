package mask

import (
	"regexp"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

func newMasker(t *testing.T, allow ...string) (*Masker, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	det, err := detect.New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var re []*regexp.Regexp
	for _, a := range allow {
		re = append(re, regexp.MustCompile(a))
	}
	return New(det, st, re), st
}

func TestMaskRoundTrip(t *testing.T) {
	m, st := newMasker(t)
	in := "key " + testsecret.AWSAccessKey() + " and mail bob@corp.dev"
	stats := Stats{}
	out, err := m.String(in, stats)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, testsecret.AWSAccessKey()) || strings.Contains(out, "bob@corp.dev") {
		t.Fatalf("leaked: %s", out)
	}
	if stats["AWS_ACCESS_KEY"] != 1 || stats["EMAIL"] != 1 {
		t.Fatalf("stats %v", stats)
	}
	back, _ := unmask.Replace(out, st, unmask.Identity)
	if back != in {
		t.Fatalf("round trip: %q", back)
	}
	again, _ := m.String(in, Stats{})
	if again != out {
		t.Fatal("masking is not deterministic")
	}
}

func TestPlaceholdersAreKept(t *testing.T) {
	m, _ := newMasker(t)
	in := "x " + placeholder.Format("EMAIL", "0123456789ab") + " y"
	out, _ := m.String(in, Stats{})
	if out != in {
		t.Fatalf("placeholder altered: %q", out)
	}
}

// A value first found by a contextual rule is masked later without context.
func TestKnownValueWithoutContext(t *testing.T) {
	m, _ := newMasker(t)
	first, _ := m.String(`password: "Tr0ub4dor&3x"`, Stats{})
	if strings.Contains(first, "Tr0ub4dor&3x") {
		t.Fatalf("not masked: %s", first)
	}
	later, _ := m.String(`const p = "Tr0ub4dor&3x"`, Stats{})
	if strings.Contains(later, "Tr0ub4dor&3x") {
		t.Fatalf("known value leaked: %s", later)
	}
}

func TestAllowlist(t *testing.T) {
	m, _ := newMasker(t, `@corp\.dev$`)
	out, _ := m.String("mail bob@corp.dev", Stats{})
	if out != "mail bob@corp.dev" {
		t.Fatalf("allowlisted value masked: %s", out)
	}
}

func TestCacheSeesNewKnownValues(t *testing.T) {
	m, _ := newMasker(t)
	long := strings.Repeat("filler text ", 40) + `const p = "N3wSecret!xyz"`
	if out, _ := m.String(long, Stats{}); out != long {
		t.Fatalf("unexpected masking: %s", out)
	}
	m.String(`password: "N3wSecret!xyz"`, Stats{})
	out, _ := m.String(long, Stats{})
	if strings.Contains(out, "N3wSecret!xyz") {
		t.Fatal("stale cache leaked a newly known value")
	}
}
