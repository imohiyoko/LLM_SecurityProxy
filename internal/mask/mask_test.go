package mask

import (
	"regexp"
	"strings"
	"sync"
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

// A value learned by a concurrent request while a string is being masked is
// not hidden by the cache on the next turn (#34).
func TestCacheIgnoresValueLearnedDuringMask(t *testing.T) {
	m, _ := newMasker(t)
	long := strings.Repeat("filler text ", 40) + `const p = "N3wSecret!xyz"`
	other := New(m.det, m.store, nil)
	m.afterMask = func() {
		m.afterMask = nil
		other.String(`password: "N3wSecret!xyz"`, Stats{}, nil)
	}
	if out, _ := m.String(long, Stats{}, nil); out != long {
		t.Fatalf("unexpected masking: %s", out)
	}
	for turn := 1; turn <= 3; turn++ {
		if out, _ := m.String(long, Stats{}, nil); strings.Contains(out, "N3wSecret!xyz") {
			t.Fatalf("turn %d: cache leaked a value learned concurrently: %s", turn, out)
		}
	}
}

// Concurrent calls never leave a cached result that misses a known value.
func TestCacheConcurrentLearn(t *testing.T) {
	for i := 0; i < 50; i++ {
		m, _ := newMasker(t)
		long := strings.Repeat("filler text ", 40) + `const p = "N3wSecret!xyz"`
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); m.String(`password: "N3wSecret!xyz"`, Stats{}, nil) }()
		go func() { defer wg.Done(); m.String(long, Stats{}, nil) }()
		wg.Wait()
		if out, _ := m.String(long, Stats{}, nil); strings.Contains(out, "N3wSecret!xyz") {
			t.Fatalf("run %d: cache leaked a value learned concurrently", i)
		}
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

// A field value that runs into a secret, or stops inside one, never takes the
// secret's place: the secret is masked whole, and what is left of the field
// value is masked as NAME around it.
func TestFieldValueDoesNotHideSecrets(t *testing.T) {
	pw := "Zx=9Kq2Lm7Pw"
	for _, c := range []struct{ in, secret string }{
		{"display_name: Deploy via https://deploy:" + pw + "@10.0.0.5/repo", pw},
		{"username: svc pwd:Hq)8vT2nW4rZ", "Hq)8vT2nW4rZ"},
		{"nickname: ops " + testsecret.PrivateKey(), testsecret.PrivateKey()},
		{"display_name: Jane " + testsecret.GitHubToken(), testsecret.GitHubToken()},
	} {
		m, st := newMasker(t)
		out, err := m.String(c.in, Stats{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{c.secret, c.secret[len(c.secret)/2:]} {
			if strings.Contains(out, part) {
				t.Errorf("%q: secret leaked: %s", c.in, out)
			}
		}
		if back, _ := unmask.Replace(out, st, unmask.Identity); back != c.in {
			t.Errorf("round trip: %q", back)
		}
	}
}

// An allowlisted span is dropped before overlaps are resolved, so it cannot
// shield a secret inside it.
func TestAllowedSpanDoesNotShieldSecret(t *testing.T) {
	m, _ := newMasker(t, `@users\.noreply\.github\.com$`, `example\.com`)
	tok := testsecret.GitHubToken()
	for _, in := range []string{
		"author_name: Jane Doe <" + tok + "> 1+jd@users.noreply.github.com",
		`{"full_name": "Jane <jane@example.com> key ` + testsecret.AnthropicKey() + `"}`,
	} {
		out, _ := m.String(in, Stats{}, nil)
		if strings.Contains(out, tok) || strings.Contains(out, testsecret.AnthropicKey()) {
			t.Errorf("secret leaked: %s", out)
		}
	}
	out, _ := m.Field("display_name", "Jane "+tok+" jd@example.com", Stats{}, nil)
	if strings.Contains(out, tok) {
		t.Errorf("Field: secret leaked: %s", out)
	}
}

// A placeholder inside a field value is kept, and the name next to it is
// still masked.
func TestFieldValueAroundPlaceholder(t *testing.T) {
	m, _ := newMasker(t)
	first, _ := m.String("mail bob@corp.dev", Stats{}, nil)
	ph := placeholder.Pattern.FindString(first)
	out, _ := m.String(`display_name: "Jane Doe `+ph+`"`, Stats{}, nil)
	if strings.Contains(out, "Jane") || !strings.Contains(out, ph) {
		t.Fatalf("got %s", out)
	}
}

// A name with JSON escapes is masked in pieces, so that it restores without
// extra backslashes, and is learned unescaped for the known-value pass.
func TestEscapedFieldValue(t *testing.T) {
	m, st := newMasker(t)
	in := `{"displayName": "Jane \"JD\" Doe"}`
	out, _ := m.String(in, Stats{}, nil)
	if strings.Contains(out, "Jane") || strings.Contains(out, "Doe") {
		t.Fatalf("not masked: %s", out)
	}
	if back, _ := unmask.Replace(out, st, unmask.Identity); back != in {
		t.Fatalf("round trip: %q", back)
	}
	later, _ := m.String(`Jane "JD" Doe joined`, Stats{}, nil)
	if strings.Contains(later, "Jane") {
		t.Fatalf("decoded name not known: %s", later)
	}
}
