package unmask

import (
	"strings"
	"testing"
)

type mapResolver map[string]string

func (m mapResolver) Resolve(id string) (string, bool) { v, ok := m[id]; return v, ok }

var res = mapResolver{
	"0123456789ab": "alice@corp.dev",
	"ba9876543210": `pa"ss\word`,
}

func TestReplace(t *testing.T) {
	in := "to __LLMSP_EMAIL_0123456789ab__, keep __LLMSP_X_ffffffffffff__"
	out, n := Replace(in, res, Identity)
	if out != "to alice@corp.dev, keep __LLMSP_X_ffffffffffff__" || n != 1 {
		t.Fatalf("%q %d", out, n)
	}
	out, _ = Replace(`{"p":"__LLMSP_SECRET_ba9876543210__"}`, res, JSONString)
	if out != `{"p":"pa\"ss\\word"}` {
		t.Fatalf("json escape: %s", out)
	}
}

// Every way of cutting the input into two or three chunks must give the same
// result as unmasking it whole.
func TestStreamAllSplits(t *testing.T) {
	in := "a_b __LLMSP_EMAIL_0123456789ab__ mid __LLMSP_AWS_SECRET_KEY_ba9876543210__ __LLMSP_ end_"
	want, _ := Replace(in, res, Identity)
	for i := 0; i <= len(in); i++ {
		for j := i; j <= len(in); j++ {
			s := NewStream(res, Identity)
			got := s.Write(in[:i]) + s.Write(in[i:j]) + s.Write(in[j:]) + s.Flush()
			if got != want {
				t.Fatalf("split %d/%d: got %q want %q", i, j, got, want)
			}
		}
	}
}

func TestStreamCharByChar(t *testing.T) {
	in := strings.Repeat("x __LLMSP_EMAIL_0123456789ab__ ", 5)
	want, _ := Replace(in, res, Identity)
	s := NewStream(res, Identity)
	var b strings.Builder
	for i := range len(in) {
		b.WriteString(s.Write(in[i : i+1]))
	}
	b.WriteString(s.Flush())
	if b.String() != want || s.Count != 5 {
		t.Fatalf("got %q (%d)", b.String(), s.Count)
	}
}

func TestStreamDoesNotHoldPlainText(t *testing.T) {
	s := NewStream(res, Identity)
	if out := s.Write("hello world"); out != "hello world" {
		t.Fatalf("held plain text: %q", out)
	}
	if out := s.Write("snake_case"); out != "snake_case" {
		t.Fatalf("held identifier: %q", out)
	}
}
