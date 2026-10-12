package mask

import (
	"regexp"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
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
	det, err := rules.Default()
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
	out, err := m.String(in, stats, nil)
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
	again, _ := m.String(in, Stats{}, nil)
	if again != out {
		t.Fatal("masking is not deterministic")
	}
}

// Placeholder-shaped text this store did not issue is masked, and restores.
func TestUnissuedPlaceholderIsMasked(t *testing.T) {
	m, st := newMasker(t)
	in := "x " + placeholder.Format("EMAIL", "0123456789ab") + " y"
	out, _ := m.String(in, Stats{}, nil)
	if strings.Contains(out, "0123456789ab") {
		t.Fatalf("unissued placeholder forwarded: %q", out)
	}
	if back, _ := unmask.Replace(out, st, unmask.Identity); back != in {
		t.Fatalf("round trip: %q", back)
	}
}

// A value first found by a contextual rule is masked later without context.
func TestKnownValueWithoutContext(t *testing.T) {
	m, _ := newMasker(t)
	first, _ := m.String(`password: "Tr0ub4dor&3x"`, Stats{}, nil)
	if strings.Contains(first, "Tr0ub4dor&3x") {
		t.Fatalf("not masked: %s", first)
	}
	later, _ := m.String(`const p = "Tr0ub4dor&3x"`, Stats{}, nil)
	if strings.Contains(later, "Tr0ub4dor&3x") {
		t.Fatalf("known value leaked: %s", later)
	}
}

func TestAllowlist(t *testing.T) {
	m, _ := newMasker(t, `@corp\.dev$`)
	out, _ := m.String("mail bob@corp.dev", Stats{}, nil)
	if out != "mail bob@corp.dev" {
		t.Fatalf("allowlisted value masked: %s", out)
	}
}

func TestCacheSeesNewKnownValues(t *testing.T) {
	m, _ := newMasker(t)
	long := strings.Repeat("filler text ", 40) + `const p = "N3wSecret!xyz"`
	if out, _ := m.String(long, Stats{}, nil); out != long {
		t.Fatalf("unexpected masking: %s", out)
	}
	m.String(`password: "N3wSecret!xyz"`, Stats{}, nil)
	out, _ := m.String(long, Stats{}, nil)
	if strings.Contains(out, "N3wSecret!xyz") {
		t.Fatal("stale cache leaked a newly known value")
	}
}

// A secret dressed up as a placeholder is not protected (#6).
func TestFakePlaceholderIsMasked(t *testing.T) {
	m, st := newMasker(t)
	key := testsecret.AWSAccessKey()
	for _, in := range []string{
		"key " + placeholder.Prefix + key + "_0123456789ab__ here",
		// A real ID does not help when the kind is not the stored one.
		"key " + placeholder.Prefix + key + "_" + st.ID("bob@corp.dev") + "__ here",
	} {
		m.String("mail bob@corp.dev", Stats{}, nil)
		out, err := m.String(in, Stats{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, key) {
			t.Fatalf("secret forwarded inside a fake placeholder: %s", out)
		}
	}
}

func TestIssuedPlaceholderIsKept(t *testing.T) {
	m, _ := newMasker(t)
	ph, _ := m.String("bob@corp.dev", Stats{}, nil)
	ids := IDs{}
	if out, _ := m.String("x "+ph+" y", Stats{}, ids); out != "x "+ph+" y" {
		t.Fatalf("issued placeholder altered: %q", out)
	}
	if len(ids) != 0 {
		t.Fatalf("a placeholder copied from the input was reported as issued: %v", ids)
	}
}

func TestIDsReportIssuedPlaceholders(t *testing.T) {
	m, st := newMasker(t)
	long := strings.Repeat("filler text ", 40) + "mail bob@corp.dev"
	want := st.ID("bob@corp.dev")
	for range 2 { // second call is served from the cache
		ids := IDs{}
		if _, err := m.String(long, Stats{}, ids); err != nil {
			t.Fatal(err)
		}
		if !ids[want] || len(ids) != 1 {
			t.Fatalf("ids %v, want %s", ids, want)
		}
	}
}

// A 19-digit card overlaps the 16-digit reading of its first groups; the
// whole card is masked, not just its prefix.
func TestNineteenDigitCardMaskedWhole(t *testing.T) {
	m, _ := newMasker(t)
	card := "6011" + " 0000 0000 0000 001"
	out, err := m.String("card "+card+" exp 12/29", Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`^card ` + placeholder.Pattern.String() + ` exp 12/29$`)
	if !want.MatchString(out) {
		t.Errorf("got %q, want the card replaced by one placeholder", out)
	}
}

// A value read from a field is masked whole and, once stored, masked again by
// exact match without its field name (the known-value pass).
func TestFieldValuePropagates(t *testing.T) {
	m, st := newMasker(t)
	in := `{"userName": "Jane Doe"}`
	out, _ := m.String(in, Stats{}, nil)
	if strings.Contains(out, "Jane") || !strings.Contains(out, "__LLMSP_NAME_") {
		t.Fatalf("field value not masked: %s", out)
	}
	if back, _ := unmask.Replace(out, st, unmask.Identity); back != in {
		t.Fatalf("round trip: %q", back)
	}
	stats := Stats{}
	later, _ := m.String("Jane Doe joined the call", stats, nil)
	if strings.Contains(later, "Jane Doe") || stats["NAME"] != 1 {
		t.Fatalf("known name not masked in free text: %s %v", later, stats)
	}
}

// Field-derived values follow the same known-value policy as every other
// value: at least MinKnownLen bytes, matched anywhere. A shorter value is
// masked in its field but not in free text.
func TestFieldValueKnownPolicy(t *testing.T) {
	m, _ := newMasker(t)
	m.String("first_name: Bob\nlast_name: Jordan\n", Stats{}, nil)
	out, _ := m.String("Bob met Jordan in Jordanian", Stats{}, nil)
	if !strings.HasPrefix(out, "Bob met __LLMSP_NAME_") || strings.Contains(out, "Jordan") {
		t.Fatalf("policy changed: %s", out)
	}
}

func TestFieldByKey(t *testing.T) {
	m, st := newMasker(t)
	stats := Stats{}
	out, err := m.Field("displayName", "Jane Doe", stats, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "__LLMSP_NAME_") || stats["NAME"] != 1 {
		t.Fatalf("not masked whole: %s %v", out, stats)
	}
	if back, _ := unmask.Replace(out, st, unmask.Identity); back != "Jane Doe" {
		t.Fatalf("round trip: %q", back)
	}
	// Allowed values and other names fall back to ordinary masking.
	for _, c := range [][2]string{{"userName", "admin"}, {"title", "Jane Roe"}} {
		if out, _ := m.Field(c[0], c[1], Stats{}, nil); out != c[1] {
			t.Errorf("Field(%q, %q) = %q", c[0], c[1], out)
		}
	}
	if out, _ := m.Field("title", "mail bob@corp.dev", Stats{}, nil); strings.Contains(out, "bob@corp.dev") {
		t.Errorf("fallback did not mask: %s", out)
	}
}
