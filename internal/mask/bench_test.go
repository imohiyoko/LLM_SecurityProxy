package mask

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

// benchText is n bytes of code-like words with no secrets in them.
func benchText(seed int64, n int) string {
	r := rand.New(rand.NewSource(seed))
	words := []string{"func", "return", "the", "value", "config", "error", "if", "for", "range", "string", "int", "map", "nil", "user", "request"}
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
		if r.Intn(10) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func benchMasker(b *testing.B, values int) *Masker {
	b.Helper()
	st, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	for i := 0; i < values; i++ {
		if _, _, err := st.Put("SECRET", fmt.Sprintf("val-%08d-xyz", i)); err != nil {
			b.Fatal(err)
		}
	}
	det, err := rules.Default()
	if err != nil {
		b.Fatal(err)
	}
	return New(det, st, nil)
}

// BenchmarkKnownValues masks 10 KB of new text with many values stored: the
// cost should not grow with the number of values.
func BenchmarkKnownValues(b *testing.B) {
	for _, n := range []int{0, 1000, 10000} {
		b.Run(fmt.Sprintf("values=%d", n), func(b *testing.B) {
			m := benchMasker(b, n)
			m.String(benchText(-1, 10_000), Stats{}, nil) // builds the index
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.String(benchText(int64(i), 10_000), Stats{}, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTurn is one turn of a conversation: 100 history messages of 2 KB
// resent unchanged, and one new message that holds a new secret.
func BenchmarkTurn(b *testing.B) {
	m := benchMasker(b, 1000)
	history := make([]string, 100)
	for i := range history {
		history[i] = benchText(int64(i), 2000)
	}
	for _, h := range history {
		m.String(h, Stats{}, nil)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, h := range history {
			if _, err := m.String(h, Stats{}, nil); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := m.String(fmt.Sprintf(`password: "turn-secret-%d"`, i), Stats{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}
