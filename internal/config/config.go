// Package config loads the YAML configuration.
//
// Environment-specific values (upstream proxy, internal host names, customer
// names) belong in the user's own config and ruleset files, never in this
// repository.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	return c, nil
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
