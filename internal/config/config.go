// Package config loads the YAML configuration.
//
// Environment-specific values (upstream proxy, internal host names, customer
// names) belong in the user's own config and ruleset files, never in this
// repository.
package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the file format. See config.example.yaml.
type Config struct {
	Listen           string   `yaml:"listen"`
	AllowNonLoopback bool     `yaml:"allow_non_loopback"`
	DataDir          string   `yaml:"data_dir"`
	InjectNotice     *bool    `yaml:"inject_notice"`
	Upstream         Upstream `yaml:"upstream"`
	Rulesets         Rulesets `yaml:"rulesets"`
	// Allowlist values are never masked, whichever rule matched them.
	Allowlist []string `yaml:"allowlist"`
	// Profiles are named listeners, each with its own upstream: one per
	// client, say. Unset upstream fields and inject_notice fall back to the
	// top-level ones. With profiles, the top-level listen is not used.
	Profiles map[string]Profile `yaml:"profiles"`

	listenSet bool
}

// Profile is one listener and where its requests go.
type Profile struct {
	Listen       string   `yaml:"listen"`
	InjectNotice *bool    `yaml:"inject_notice"`
	Upstream     Upstream `yaml:"upstream"`
}

// Endpoint is a resolved profile: what one listener serves.
type Endpoint struct {
	Name         string
	Listen       string
	Upstream     Upstream
	InjectNotice bool
}

// Upstream describes where requests go.
type Upstream struct {
	BaseURL string `yaml:"base_url"`
	// Proxy is an HTTP(S) proxy URL. Empty means HTTPS_PROXY / HTTP_PROXY.
	Proxy string `yaml:"proxy"`
	// CAFile adds PEM certificates to the trust store (TLS-inspecting proxies).
	CAFile string `yaml:"ca_file"`
	// AuthHeaders carry the upstream credential and are forwarded unmasked.
	// Every other header value is masked like body content.
	AuthHeaders []string `yaml:"auth_headers"`
}

// Rulesets selects detection rules. See internal/rules.
type Rulesets struct {
	// Dirs are extra directories of ruleset files. <config dir>/rules.d is
	// always read if it exists.
	Dirs []string `yaml:"dirs"`
	// Enable / Disable take ruleset IDs ("builtin/network") or rule IDs
	// ("builtin/pii:email"). Disable wins.
	Enable  []string `yaml:"enable"`
	Disable []string `yaml:"disable"`
}

// DefaultDir is where config, rules, key and database live by default.
func DefaultDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "llmsp"), nil
}

// Load reads path. A missing file is an error only if mustExist.
func Load(path string, mustExist bool) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist) && !mustExist:
	default:
		return nil, err
	}
	c.listenSet = c.Listen != ""
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	if c.Upstream.BaseURL == "" {
		c.Upstream.BaseURL = "https://api.anthropic.com"
	}
	if c.Upstream.AuthHeaders == nil {
		c.Upstream.AuthHeaders = []string{"Authorization", "X-Api-Key"}
	}
	if c.DataDir == "" {
		c.DataDir = filepath.Dir(path)
	}
	c.DataDir = expandHome(c.DataDir)
	c.Upstream.CAFile = expandHome(c.Upstream.CAFile)
	if len(c.Profiles) > 0 && c.listenSet {
		return nil, fmt.Errorf("config %s: listen and profiles are both set; give each profile its own listen", path)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Profiles)) {
		if !profileName.MatchString(name) {
			return nil, fmt.Errorf("config %s: profile %q: name must be lowercase letters, digits, - and _", path, name)
		}
		if c.Profiles[name].Listen == "" {
			return nil, fmt.Errorf("config %s: profile %s: listen is required", path, name)
		}
	}
	return c, nil
}

var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Select returns the listeners to serve. profile empty: every profile, or
// without profiles the top-level listen and upstream, named "default".
// Otherwise only that profile ("default" when there are none), so a bad
// address in another profile does not stop it. listen, if set, replaces the
// address of the one listener selected; with several it is an error.
// Addresses are resolved, and two listeners on one address are an error:
// [::1]:8787 and [0:0:0:0:0:0:0:1]:8787, or localhost:8787 and
// 127.0.0.1:8787, are the same listener.
func (c *Config) Select(profile, listen string) ([]Endpoint, error) {
	var out []Endpoint
	switch {
	case len(c.Profiles) == 0 && (profile == "" || profile == "default"):
		out = []Endpoint{{Name: "default", Listen: c.Listen, Upstream: c.Upstream, InjectNotice: c.Notice()}}
	case len(c.Profiles) == 0:
		return nil, fmt.Errorf("profile %s: the config has no profiles", profile)
	case profile == "":
		for _, name := range slices.Sorted(maps.Keys(c.Profiles)) {
			out = append(out, c.endpoint(name))
		}
		if listen != "" {
			return nil, errors.New("listen override with several profiles: select one profile")
		}
	default:
		if _, ok := c.Profiles[profile]; !ok {
			return nil, fmt.Errorf("profile %s: no such profile in the config", profile)
		}
		out = []Endpoint{c.endpoint(profile)}
	}
	if listen != "" {
		out[0].Listen = listen
	}
	seen := map[string]string{}
	for _, e := range out {
		addr, err := net.ResolveTCPAddr("tcp", e.Listen)
		if err != nil {
			return nil, fmt.Errorf("profile %s: listen: %w", e.Name, err)
		}
		key := addr.String()
		if other, ok := seen[key]; ok {
			return nil, fmt.Errorf("profiles %s and %s both listen on %s", other, e.Name, key)
		}
		seen[key] = e.Name
	}
	return out, nil
}

// Endpoints is Select("", ""): every listener.
func (c *Config) Endpoints() ([]Endpoint, error) { return c.Select("", "") }

// endpoint resolves profile name against the top-level defaults.
func (c *Config) endpoint(name string) Endpoint {
	p := c.Profiles[name]
	e := Endpoint{Name: name, Listen: p.Listen, Upstream: c.Upstream, InjectNotice: c.Notice()}
	if u := p.Upstream; u.BaseURL != "" {
		e.Upstream.BaseURL = u.BaseURL
	}
	if u := p.Upstream; u.Proxy != "" {
		e.Upstream.Proxy = u.Proxy
	}
	if u := p.Upstream; u.CAFile != "" {
		e.Upstream.CAFile = expandHome(u.CAFile)
	}
	if u := p.Upstream; u.AuthHeaders != nil {
		e.Upstream.AuthHeaders = u.AuthHeaders
	}
	if p.InjectNotice != nil {
		e.InjectNotice = *p.InjectNotice
	}
	return e
}

// Notice reports whether the system prompt notice is injected (default true).
func (c *Config) Notice() bool { return c.InjectNotice == nil || *c.InjectNotice }

// RuleDirs returns the directories to load rulesets from.
func (c *Config) RuleDirs(configDir string) []string {
	dirs := []string{filepath.Join(configDir, "rules.d")}
	for _, d := range c.Rulesets.Dirs {
		dirs = append(dirs, expandHome(d))
	}
	return dirs
}

// AllowPatterns compiles the allowlist.
func (c *Config) AllowPatterns() ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range c.Allowlist {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("allowlist %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[1:])
		}
	}
	return p
}
