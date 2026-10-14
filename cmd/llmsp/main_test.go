package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
)

// Each profile masks with its own rules and allowlist.
func TestProfilesMaskDifferently(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(`
profiles:
  standard:
    listen: 127.0.0.1:9001
  strict:
    listen: 127.0.0.1:9002
    rulesets:
      enable: [builtin/network]
  light:
    listen: 127.0.0.1:9003
    rulesets:
      disable: [builtin/pii]
    allowlist: ['@example\.org$']
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := rules.Load(cfg.RuleDirs(dir))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{cfg: cfg, catalog: catalog}
	eps, err := cfg.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	const text = "host 10.1.2.3 mail bob@corp.dev"
	want := map[string]int{"light": 0, "standard": 1, "strict": 2}
	for _, ep := range eps {
		det, allow, err := e.masking(ep)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(det.Find(text)); got != want[ep.Name] {
			t.Errorf("%s: %d matches, want %d", ep.Name, got, want[ep.Name])
		}
		if wantAllow := ep.Name == "light"; (len(allow) == 1) != wantAllow {
			t.Errorf("%s: allowlist %v", ep.Name, allow)
		}
	}
}
