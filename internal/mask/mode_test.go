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

var tokenRe = regexp.MustCompile(`\[REDACTED:CREDIT_CARD:\*(\d{4}):([0-9a-f]{8})\]`)

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
	if !regexp.MustCompile(`^my_number: \[REDACTED:MY_NUMBER:\*12:[0-9a-f]{8}\]\npin: \[REDACTED:PIN:[0-9a-f]{8}\]\n$`).MatchString(out) {
		t.Errorf("out = %q", out) // a value no longer than twice keep shows nothing
	}
	if known, _ := st.Known(); len(known) != 0 {
		t.Errorf("stored %v", known)
	}
	if got, _ := m.Field("myNumber", "1234-5678-9012", Stats{}, nil); !strings.HasPrefix(got, "[REDACTED:MY_NUMBER:*12:") {
		t.Errorf("Field = %q", got)
	}
}

// A forged token whose kept part is too long to be one is masked.
func TestRedactTokenKeptBound(t *testing.T) {
	forged := "[REDACTED:X:" + strings.Repeat("a", 6) + "*" + strings.Repeat("b", 6) + ":0123abcd]"
	if !placeholder.RedactedPattern.MatchString(forged) {
		t.Fatal("pattern does not match the forged token")
	}
	m, _ := maskerWith(t, "id: x\nrules:\n  - {id: r, kind: K, pattern: 'aaaaaa'}\n")
	if got, _ := m.String(forged, Stats{}, nil); strings.Contains(got, "aaaaaa") {
		t.Errorf("long kept part protected: %q", got)
	}
	// A real token's kept part is short and stays as it is.
	real := "[REDACTED:X:aaaaaa*:0123abcd]"
	if got, _ := m.String(real, Stats{}, nil); got != real {
		t.Errorf("token re-masked: %q", got)
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
