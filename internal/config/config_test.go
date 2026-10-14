package config

import (
	"fmt"
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
		"dirs in a profile":           {"profiles:\n  a:\n    listen: 127.0.0.1:9001\n    rulesets:\n      dirs: [x]\n", "not found"},
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

func TestProfileMasking(t *testing.T) {
	c, err := load(t, `
rulesets:
  enable: [builtin/network]
  disable: [builtin/pii:email]
allowlist: ['^top$']
profiles:
  plain:
    listen: 127.0.0.1:9001
  strict:
    listen: 127.0.0.1:9002
    rulesets:
      enable: [builtin/pii:email]
    allowlist: []
  light:
    listen: 127.0.0.1:9003
    rulesets:
      disable: [builtin/network, builtin/pii]
    allowlist: ['^own$']
`)
	if err != nil {
		t.Fatal(err)
	}
	eps, err := c.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range eps {
		got[e.Name] = fmt.Sprintf("enable=%v disable=%v allow=%v", e.Enable, e.Disable, e.Allowlist)
	}
	want := map[string]string{
		// Nothing set: the top-level selection.
		"plain": "enable=[builtin/network] disable=[builtin/pii:email] allow=[^top$]",
		// Enabling what the top level disables turns it back on.
		"strict": "enable=[builtin/network builtin/pii:email] disable=[] allow=[^top$]",
		// Disabling what the top level enables turns it off; the allowlist adds.
		"light": "enable=[] disable=[builtin/pii:email builtin/network builtin/pii] allow=[^top$ ^own$]",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %s\n want %s", name, got[name], w)
		}
	}

	top, err := c.Masking("")
	if err != nil || top.Name != "default" || fmt.Sprint(top.Enable) != "[builtin/network]" {
		t.Errorf("Masking(\"\") = %+v, %v; want the top-level selection", top, err)
	}
	if ep, err := c.Masking("light"); err != nil || fmt.Sprint(ep.Allowlist) != "[^top$ ^own$]" {
		t.Errorf("Masking(light) = %+v, %v", ep, err)
	}
	if _, err := c.Masking("nope"); err == nil {
		t.Error("Masking(nope): want an error")
	}
}

func TestRoutes(t *testing.T) {
	c, err := load(t, `
listen: 127.0.0.1:9000
upstream:
  base_url: https://llm.example.com
profiles:
  claude:
    rulesets:
      enable: [builtin/network]
  codex:
    upstream:
      base_url: https://openai.example.com/v1
  own:
    listen: 127.0.0.1:9001
routes:
  - client: claude-code
    profile: claude
  - client: codex
    profile: codex
  - profile: default
`)
	if err != nil {
		t.Fatal(err)
	}
	eps, err := c.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].Name != "default" || eps[0].Listen != "127.0.0.1:9000" || eps[1].Name != "own" {
		t.Fatalf("want the routing listener and own: got %+v", eps)
	}
	rs := eps[0].Routes
	if len(rs) != 3 || rs[0].Endpoint.Name != "claude" || fmt.Sprint(rs[0].Endpoint.Enable) != "[builtin/network]" ||
		rs[1].Endpoint.Upstream.BaseURL != "https://openai.example.com/v1" || rs[2].Endpoint.Name != "default" {
		t.Errorf("routes resolve to their profiles: got %+v", rs)
	}
	if eps[1].Routes != nil {
		t.Error("only the top-level listener routes")
	}

	for name, tc := range map[string]struct{ profile, listen, want string }{
		"default only":         {"default", "", "default@127.0.0.1:9000"},
		"routed, own listen":   {"codex", "127.0.0.1:9100", "codex@127.0.0.1:9100"},
		"routed, no listen":    {"codex", "", "error: served through routes"},
		"all, listen override": {"", "127.0.0.1:9100", "error: select one profile"},
	} {
		t.Run(name, func(t *testing.T) {
			eps, err := c.Select(tc.profile, tc.listen)
			got := ""
			if err != nil {
				got = "error: " + err.Error()
			} else {
				got = eps[0].Name + "@" + eps[0].Listen
			}
			if want, isErr := strings.CutPrefix(tc.want, "error: "); isErr {
				if !strings.Contains(got, want) {
					t.Errorf("got %q, want an error containing %q", got, want)
				}
			} else if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRouteErrors(t *testing.T) {
	const profiles = "profiles:\n  a: {}\nroutes:\n"
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown profile":              {profiles + "  - profile: b\n", "no such profile"},
		"no profile":                   {profiles + "  - client: codex\n", "profile is required"},
		"unknown client":               {profiles + "  - client: vim\n    profile: a\n", "known clients"},
		"bad pattern":                  {profiles + "  - header: {X-A: '('}\n    profile: a\n", "header X-A"},
		"bad prefix":                   {profiles + "  - path_prefix: cline/\n    profile: a\n", "path_prefix"},
		"catch-all not last":           {profiles + "  - profile: a\n  - client: codex\n    profile: a\n", "never used"},
		"no routes, listen":            {"listen: 127.0.0.1:9000\nprofiles:\n  a:\n    listen: 127.0.0.1:9001\n", "both set"},
		"no routes, no profile listen": {"profiles:\n  a: {}\n", "listen is required"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
