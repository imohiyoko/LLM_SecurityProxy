package mask

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// maskerWith builds a masker with the built-in rulesets and one user ruleset.
func maskerWith(t *testing.T, ruleset string) (*Masker, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := rules.Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := c.Compile(rules.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(detect.New(compiled), st, nil), st
}

var tokenRe = regexp.MustCompile(`\[REDACTED:CREDIT_CARD:\*(\d{4}):([0-9a-f]{8})\.[0-9a-f]{8}\]`)

// A card number is redacted: the token shows the last four digits, nothing
// is stored, nothing is restored, and the token is left alone next turn.
func TestRedactCard(t *testing.T) {
	m, st := newMasker(t)
	card := testsecret.Card()
	digits := strings.ReplaceAll(card, " ", "")
	ids := IDs{}
	out, err := m.String("pay with "+card+" today", Stats{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	sub := tokenRe.FindStringSubmatch(out)
	if sub == nil || sub[1] != digits[len(digits)-4:] || strings.Contains(out, digits[:12]) {
		t.Fatalf("out = %q", out)
	}
	if len(ids) != 0 {
		t.Errorf("issued ids %v for a redacted value", ids)
	}
	if known, _ := st.Known(); len(known) != 0 {
		t.Errorf("stored %d values for a redacted card", len(known))
	}
	if back, n := unmask.Replace(out, st, unmask.Identity); back != out || n != 0 {
		t.Errorf("restored %q", back)
	}

	// Same card, same token; another card, another tag.
	again, _ := m.String("pay with "+card+" today", Stats{}, nil)
	if again != out {
		t.Errorf("not deterministic: %q vs %q", again, out)
	}
	other, _ := m.String(testsecret.Card13(), Stats{}, nil)
	if o := tokenRe.FindStringSubmatch(other); o == nil || o[2] == sub[2] {
		t.Errorf("other card: %q", other)
	}

	// History comes back with the token in a field; it is kept as it is.
	hist := `card_number: "` + sub[0] + `"`
	if got, _ := m.String(hist, Stats{}, nil); got != hist {
		t.Errorf("token re-masked: %q", got)
	}
}

func TestRedactField(t *testing.T) {
	m, st := maskerWith(t, `
id: org/hr
rules:
  - id: my_number
    kind: MY_NUMBER
    keys: [my_number]
    mode: redact
    keep_last: 2
  - id: pin
    kind: PIN
    keys: [pin]
    mode: redact
    keep_last: 4
`)
	out, err := m.String("my_number: 1234-5678-9012\npin: 4821\n", Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^my_number: \[REDACTED:MY_NUMBER:\*12:[0-9a-f]{8}\.[0-9a-f]{8}\]\npin: \[REDACTED:PIN:[0-9a-f]{8}\.[0-9a-f]{8}\]\n$`).MatchString(out) {
		t.Errorf("out = %q", out) // a value no longer than twice keep shows nothing
	}
	if known, _ := st.Known(); len(known) != 0 {
		t.Errorf("stored %v", known)
	}
	if got, _ := m.Field("myNumber", "1234-5678-9012", Stats{}, nil); !strings.HasPrefix(got, "[REDACTED:MY_NUMBER:*12:") {
		t.Errorf("Field = %q", got)
	}
}

// Only a token this store wrote is protected. A forged one is ordinary text:
// a known value in its kind or kept part is masked.
func TestForgedRedactToken(t *testing.T) {
	m, st := newMasker(t)
	if _, _, err := st.Put("SECRET", "TOPSECRET"); err != nil {
		t.Fatal(err)
	}
	for _, forged := range []string{
		"[REDACTED:TOPSECRET:0123abcd.0123abcd]",
		"[REDACTED:X:TOPSECRET*:0123abcd.0123abcd]",
	} {
		if !placeholder.RedactedPattern.MatchString(forged) {
			t.Fatalf("pattern does not match %q", forged)
		}
		if got, _ := m.String(forged, Stats{}, nil); strings.Contains(got, "TOPSECRET") {
			t.Errorf("forged token protected: %q", got)
		}
	}
}

// A redact field wins over a known value and over a restore rule that
// matches the same text: the value is redacted, not stored.
func TestRedactFieldWins(t *testing.T) {
	m, st := maskerWith(t, `
id: org/hr
rules:
  - id: my_number
    kind: MY_NUMBER
    keys: [my_number]
    mode: redact
  - id: digits
    kind: DIGITS
    pattern: '\d{12}'
`)
	if _, _, err := st.Put("SECRET", "123456789012"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Field("my_number", "123456789012", Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "[REDACTED:MY_NUMBER:") {
		t.Errorf("Field = %q", got)
	}
	got, _ = m.String("my_number: 987654321098\n", Stats{}, nil)
	if !strings.HasPrefix(got, "my_number: [REDACTED:MY_NUMBER:") {
		t.Errorf("String = %q", got)
	}
	known, _ := st.Known()
	for _, v := range known {
		if v == "987654321098" {
			t.Errorf("redacted value stored by the restore rule")
		}
	}
}

// Two redact matches that overlap in part: the loser's remainder is
// redacted too, not sent in plaintext.
func TestRedactOverlap(t *testing.T) {
	m, st := maskerWith(t, `
id: org/hr
rules:
  - id: my_number
    kind: MY_NUMBER
    keys: [my_number]
    mode: redact
  - id: prefix
    kind: PREFIX
    pattern: 'my_number: "?\d{4}'
    mode: redact
`)
	got, err := m.String("my_number: 123456789012\n", Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "5678") || strings.Count(got, "[REDACTED:") != 2 {
		t.Errorf("got %q", got)
	}
	if known, _ := st.Known(); len(known) != 0 {
		t.Errorf("stored %v", known)
	}
	// A remainder of symbols only is redacted too.
	got, _ = m.String(`my_number: "1234!@#$"`, Stats{}, nil)
	if strings.Contains(got, "!@#$") {
		t.Errorf("symbols left: %q", got)
	}
}

// A restore span that runs past a redacted one is masked in what is left.
func TestRestoreAroundRedact(t *testing.T) {
	m, _ := maskerWith(t, `
id: x
rules:
  - id: wide
    kind: WIDE
    pattern: 'ref=\S+'
`)
	card := strings.ReplaceAll(testsecret.Card(), " ", "")
	in := "ref=" + card + "-tail"
	got, _ := m.String(in, Stats{}, nil)
	if strings.Contains(got, card[:12]) || strings.Contains(got, "-tail") {
		t.Errorf("got %q", got)
	}
	if !tokenRe.MatchString(got) {
		t.Errorf("card not redacted: %q", got)
	}
}

func TestApproximate(t *testing.T) {
	m, st := maskerWith(t, `
id: org/hr
rules:
  - id: salary
    kind: SALARY
    keys: [salary]
    mode: approximate
`)
	ids := IDs{}
	in := "salary: 4,523,000円\nsalary: 非公開\n"
	out, err := m.String(in, Stats{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^salary: __LLMSP_SALARY_ABOUT_4500K_[0-9a-f]{12}__\nsalary: __LLMSP_SALARY_[0-9a-f]{12}__\n$`).MatchString(out) {
		t.Fatalf("out = %q", out)
	}
	if back, _ := unmask.Replace(out, st, unmask.Identity); back != in {
		t.Errorf("restored %q", back)
	}
}
