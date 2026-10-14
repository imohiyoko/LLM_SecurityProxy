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
	"time"

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
	// Routes pick a profile per request on the top-level listen address, by
	// client, header or path prefix. The first match wins; a request no
	// route matches uses the top-level settings. Profiles served only
	// through routes need no listen of their own.
	Routes []Route `yaml:"routes"`

	listenSet bool
}

// Route sends matching requests to Profile. Every condition set must hold; a
// route without conditions matches every request.
type Route struct {
	// Client is a known client, detected from the headers it sends: see
	// package route.
	Client string `yaml:"client"`
	// Header maps header names to RE2 patterns the value must match; an
	// empty pattern only requires the header to be present. Headers named
	// X-Llmsp-* are never forwarded.
	Header map[string]string `yaml:"header"`
	// PathPrefix ("/cline") matches that path and paths below it; it is
	// removed before the request is forwarded.
	PathPrefix string `yaml:"path_prefix"`
	Profile    string `yaml:"profile"`
}

// Routed is a route with its resolved profile.
type Routed struct {
	Route
	Endpoint Endpoint
}

// Profile is one listener, where its requests go and how they are masked.
type Profile struct {
	Listen       string          `yaml:"listen"`
	InjectNotice *bool           `yaml:"inject_notice"`
	Upstream     Upstream        `yaml:"upstream"`
	Rulesets     ProfileRulesets `yaml:"rulesets"`
	// Allowlist is added to the top-level one.
	Allowlist []string `yaml:"allowlist"`
	// Relax lets this profile stand in for stricter ones for a while (see
	// `llmsp relax`).
	Relax *Relax `yaml:"relax"`
}

// Relax is how a profile may be used temporarily instead of stricter ones.
type Relax struct {
	// Replaces are the profiles whose requests it serves while relaxed
	// ("default": requests no route matched).
	Replaces []string `yaml:"replaces"`
	// Default is the duration when none is given; Max the longest allowed.
	// Default omitted means Max.
	Default time.Duration `yaml:"default"`
	Max     time.Duration `yaml:"max"`
}

// ProfileRulesets turns rulesets or rules on or off for one profile, over the
// top-level selection: an ID named here overrides the same ID at the top
// level. Ruleset files are shared, so there are no dirs here.
type ProfileRulesets struct {
	Enable  []string `yaml:"enable"`
	Disable []string `yaml:"disable"`
}

// Endpoint is a resolved profile: what one listener serves.
type Endpoint struct {
	Name         string
	Listen       string
	Upstream     Upstream
	InjectNotice bool
	// Enable and Disable select its rules (see Rulesets); Allowlist are the
	// patterns it never masks.
	Enable, Disable []string
	Allowlist       []string
	// Routes, on the top-level listener only, pick another profile per
	// request; this endpoint serves requests no route matches.
	Routes []Routed
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
	routed := len(c.Routes) > 0
	if len(c.Profiles) > 0 && c.listenSet && !routed {
		return nil, fmt.Errorf("config %s: listen and profiles are both set; give each profile its own listen, or add routes", path)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Profiles)) {
		if !profileName.MatchString(name) {
			return nil, fmt.Errorf("config %s: profile %q: name must be lowercase letters, digits, - and _", path, name)
		}
		if c.Profiles[name].Listen == "" && !routed {
			return nil, fmt.Errorf("config %s: profile %s: listen is required", path, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Profiles)) {
		if err := c.checkRelax(name); err != nil {
			return nil, fmt.Errorf("config %s: profile %s: relax: %w", path, name, err)
		}
	}
	for i, r := range c.Routes {
		if err := c.checkRoute(r); err != nil {
			return nil, fmt.Errorf("config %s: routes[%d]: %w", path, i, err)
		}
		if r.matchesAll() && i < len(c.Routes)-1 {
			return nil, fmt.Errorf("config %s: routes[%d] has no conditions, so the routes after it are never used", path, i)
		}
	}
	return c, nil
}

func (c *Config) checkRelax(name string) error {
	r := c.Profiles[name].Relax
	if r == nil {
		return nil
	}
	if len(c.Routes) == 0 {
		return errors.New("needs routes: a relaxed profile serves requests of the routing listener")
	}
	if len(r.Replaces) == 0 {
		return errors.New("replaces is required")
	}
	for _, p := range r.Replaces {
		if _, ok := c.Profiles[p]; (!ok && p != "default") || p == name {
			return fmt.Errorf("replaces: %s: no such other profile", p)
		}
	}
	if r.Max <= 0 {
		return errors.New("max is required (e.g. 8h)")
	}
	if r.Default < 0 || r.Default > r.Max {
		return errors.New("default must be between 0 and max")
	}
	if r.Default == 0 {
		r.Default = r.Max
	}
	return nil
}

// RelaxLimit is the longest name may be relaxed to; ok false if it may not.
func (c *Config) RelaxLimit(name string) (time.Duration, bool) {
	p, ok := c.Profiles[name]
	if !ok || p.Relax == nil {
		return 0, false
	}
	return p.Relax.Max, true
}

// Clients are the names Route.Client accepts; package route detects them.
var Clients = []string{"claude-code", "codex", "cline"}

func (c *Config) checkRoute(r Route) error {
	if r.Profile == "" {
		return errors.New("profile is required")
	}
	if _, ok := c.Profiles[r.Profile]; !ok && r.Profile != "default" {
		return fmt.Errorf("profile %s: no such profile", r.Profile)
	}
	if r.Client != "" && !slices.Contains(Clients, r.Client) {
		return fmt.Errorf("client %q: known clients are %s", r.Client, strings.Join(Clients, ", "))
	}
	for name, pat := range r.Header {
		if name == "" || strings.ContainsAny(name, " :") {
			return fmt.Errorf("header %q: not a header name", name)
		}
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("header %s: %w", name, err)
		}
	}
	if p := r.PathPrefix; p != "" && (!strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, "//")) {
		return fmt.Errorf("path_prefix %q: must start with / and not end with /", p)
	}
	return nil
}

func (r Route) matchesAll() bool { return r.Client == "" && len(r.Header) == 0 && r.PathPrefix == "" }

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
	case len(c.Routes) > 0 && (profile == "" || profile == "default"):
		// The routing listener, then every profile with a listen of its own.
		out = []Endpoint{c.router()}
		if profile == "" {
			for _, name := range slices.Sorted(maps.Keys(c.Profiles)) {
				if c.Profiles[name].Listen != "" {
					out = append(out, c.endpoint(name))
				}
			}
		}
	case len(c.Profiles) == 0 && (profile == "" || profile == "default"):
		out = []Endpoint{c.base("default", c.Listen)}
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
	if listen != "" && len(out) > 1 {
		return nil, errors.New("listen override with several listeners: select one profile, or default for the routes")
	}
	if listen != "" {
		out[0].Listen = listen
	}
	if out[0].Listen == "" {
		return nil, fmt.Errorf("profile %s: no listen of its own; it is served through routes (or give -listen)", out[0].Name)
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

// router is the top-level listener with its routes resolved.
func (c *Config) router() Endpoint {
	e := c.base("default", c.Listen)
	for _, r := range c.Routes {
		target := c.base("default", "")
		if r.Profile != "default" {
			target = c.endpoint(r.Profile)
		}
		e.Routes = append(e.Routes, Routed{Route: r, Endpoint: target})
	}
	return e
}

// base is an endpoint with only the top-level settings.
func (c *Config) base(name, listen string) Endpoint {
	return Endpoint{
		Name: name, Listen: listen, Upstream: c.Upstream, InjectNotice: c.Notice(),
		Enable: slices.Clone(c.Rulesets.Enable), Disable: slices.Clone(c.Rulesets.Disable),
		Allowlist: slices.Clone(c.Allowlist),
	}
}

// override is ids without those in drop, plus add.
func override(ids, drop, add []string) []string {
	out := slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return slices.Contains(drop, id) })
	return append(out, add...)
}

// Endpoints is Select("", ""): every listener.
func (c *Config) Endpoints() ([]Endpoint, error) { return c.Select("", "") }

// Endpoint resolves profile name, which must exist.
func (c *Config) Endpoint(name string) Endpoint { return c.endpoint(name) }

// endpoint resolves profile name against the top-level defaults.
func (c *Config) endpoint(name string) Endpoint {
	p := c.Profiles[name]
	e := c.base(name, p.Listen)
	e.Enable = override(c.Rulesets.Enable, p.Rulesets.Disable, p.Rulesets.Enable)
	e.Disable = override(c.Rulesets.Disable, p.Rulesets.Enable, p.Rulesets.Disable)
	e.Allowlist = append(e.Allowlist, p.Allowlist...)
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

// Masking returns the endpoint whose masking settings apply to profile, for
// commands that only mask: profile empty is the top-level settings.
func (c *Config) Masking(profile string) (Endpoint, error) {
	if profile == "" || (profile == "default" && len(c.Profiles) == 0) {
		return c.base("default", c.Listen), nil
	}
	if _, ok := c.Profiles[profile]; !ok {
		return Endpoint{}, fmt.Errorf("profile %s: no such profile in the config", profile)
	}
	return c.endpoint(profile), nil
}

// AllowPatterns compiles the endpoint's allowlist.
func (e Endpoint) AllowPatterns() ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range e.Allowlist {
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
