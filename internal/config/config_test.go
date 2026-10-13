package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p, true)
}

func TestEndpointsWithoutProfiles(t *testing.T) {
	c, err := load(t, "upstream:\n  base_url: https://llm.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	eps, err := c.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Name != "default" || eps[0].Listen != "127.0.0.1:8787" ||
		eps[0].Upstream.BaseURL != "https://llm.example.com" || !eps[0].InjectNotice {
		t.Fatalf("got %+v", eps)
	}
}

func TestEndpointsProfiles(t *testing.T) {
	c, err := load(t, `
inject_notice: true
upstream:
  base_url: https://llm.example.com
  proxy: http://proxy.example.com:8080
profiles:
  claude:
    listen: 127.0.0.1:8787
  codex:
    listen: 127.0.0.1:8788
    inject_notice: false
    upstream:
      base_url: https://openai.example.com/v1
      auth_headers: [Authorization]
`)
	if err != nil {
		t.Fatal(err)
	}
	eps, err := c.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints", len(eps))
	}
	claude, codex := eps[0], eps[1]
	if claude.Name != "claude" || claude.Listen != "127.0.0.1:8787" ||
		claude.Upstream.BaseURL != "https://llm.example.com" || !claude.InjectNotice ||
		len(claude.Upstream.AuthHeaders) != 2 {
		t.Errorf("claude inherits the top level: got %+v", claude)
	}
	if codex.Name != "codex" || codex.Upstream.BaseURL != "https://openai.example.com/v1" ||
		codex.Upstream.Proxy != "http://proxy.example.com:8080" || codex.InjectNotice ||
		len(codex.Upstream.AuthHeaders) != 1 {
		t.Errorf("codex overrides only what it sets: got %+v", codex)
	}
}

func TestEndpointsInvalid(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"listen and profiles":         {"listen: 127.0.0.1:9000\nprofiles:\n  a:\n    listen: 127.0.0.1:9001\n", "both set"},
		"no listen":                   {"profiles:\n  a:\n    upstream:\n      base_url: https://x.example.com\n", "listen is required"},
		"same listen":                 {"profiles:\n  a:\n    listen: 127.0.0.1:9001\n  b:\n    listen: 127.0.0.1:9001\n", "both listen"},
		"same listen, other spelling": {"profiles:\n  a:\n    listen: '[::1]:9001'\n  b:\n    listen: '[0:0:0:0:0:0:0:1]:9001'\n", "both listen"},
		"bad listen":                  {"profiles:\n  a:\n    listen: 127.0.0.1\n", "listen:"},
		"bad name":                    {"profiles:\n  Claude Code:\n    listen: 127.0.0.1:9001\n", "name must be"},
		"unknown field":               {"profiles:\n  a:\n    listen: 127.0.0.1:9001\n    base_url: https://x.example.com\n", "not found"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := load(t, tc.yaml)
			if err == nil {
				_, err = c.Endpoints()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	const profiles = `
profiles:
  claude:
    listen: 127.0.0.1:9001
  codex:
    listen: 127.0.0.1:9002
  broken:
    listen: 127.0.0.1
  twin:
    listen: 127.0.0.1:9002
`
	const plain = "listen: 127.0.0.1:9000\n"
	for name, tc := range map[string]struct {
		yaml, profile, listen string
		want                  string // "name@listen,..." or "error: <substring>"
	}{
		"plain":                       {plain, "", "", "default@127.0.0.1:9000"},
		"plain, listen":               {plain, "", "127.0.0.1:9100", "default@127.0.0.1:9100"},
		"plain, profile default":      {plain, "default", "127.0.0.1:9100", "default@127.0.0.1:9100"},
		"plain, other profile":        {plain, "codex", "", "error: has no profiles"},
		"all profiles":                {profiles, "", "", "error: profile broken: listen"},
		"all profiles, listen":        {profiles, "", "127.0.0.1:9100", "error: select one profile"},
		"one, others broken":          {profiles, "codex", "", "codex@127.0.0.1:9002"},
		"one, listen":                 {profiles, "claude", "127.0.0.1:9100", "claude@127.0.0.1:9100"},
		"one, bad listen override":    {profiles, "claude", "127.0.0.1", "error: profile claude: listen"},
		"broken one, listen fixes it": {profiles, "broken", "127.0.0.1:9100", "broken@127.0.0.1:9100"},
		"unknown profile":             {profiles, "nope", "", "error: no such profile"},
		"default with profiles":       {profiles, "default", "", "error: no such profile"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := load(t, tc.yaml)
			if err != nil {
				t.Fatal(err)
			}
			eps, err := c.Select(tc.profile, tc.listen)
			var got string
			if err != nil {
				got = "error: " + err.Error()
			} else {
				var parts []string
				for _, e := range eps {
					parts = append(parts, e.Name+"@"+e.Listen)
				}
				got = strings.Join(parts, ",")
			}
			if want, isErr := strings.CutPrefix(tc.want, "error: "); isErr {
				if !strings.HasPrefix(got, "error: ") || !strings.Contains(got, want) {
					t.Errorf("got %q, want an error containing %q", got, want)
				}
			} else if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
