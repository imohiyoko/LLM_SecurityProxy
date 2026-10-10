// Package config loads the YAML configuration.
//
// Environment-specific values (upstream proxy, internal host names, customer
// names) belong in the user's own config file, never in this repository.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
)

// Config is the file format. See config.example.yaml.
type Config struct {
	Listen           string   `yaml:"listen"`
	AllowNonLoopback bool     `yaml:"allow_non_loopback"`
	DataDir          string   `yaml:"data_dir"`
	InjectNotice     *bool    `yaml:"inject_notice"`
	Upstream         Upstream `yaml:"upstream"`
	Detectors        struct {
		Enable  []string `yaml:"enable"`
		Disable []string `yaml:"disable"`
	} `yaml:"detectors"`
	Allowlist  []string     `yaml:"allowlist"`
	Dictionary []Dictionary `yaml:"dictionary"`
}

// Upstream describes where requests go.
type Upstream struct {
	BaseURL string `yaml:"base_url"`
	// Proxy is an HTTP(S) proxy URL. Empty means HTTPS_PROXY / HTTP_PROXY.
	Proxy string `yaml:"proxy"`
	// CAFile adds PEM certificates to the trust store (TLS-inspecting proxies).
	CAFile string `yaml:"ca_file"`
}

// Dictionary masks literal values under a kind.
type Dictionary struct {
	Kind            string   `yaml:"kind"`
	Values          []string `yaml:"values"`
	File            string   `yaml:"file"`
	CaseInsensitive bool     `yaml:"case_insensitive"`
}

// DefaultDir is where config, key and database live by default.
func DefaultDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "llmsp"), nil
}

// Load reads path. A missing file at the default location yields defaults.
func Load(path string, mustExist bool) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, c); err != nil {
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
	if c.DataDir == "" {
		c.DataDir = filepath.Dir(path)
	}
	c.DataDir = expandHome(c.DataDir)
	c.Upstream.CAFile = expandHome(c.Upstream.CAFile)
	return c, nil
}

// Notice reports whether the system prompt notice is injected (default true).
func (c *Config) Notice() bool { return c.InjectNotice == nil || *c.InjectNotice }

// DictionaryRules compiles the dictionaries.
func (c *Config) DictionaryRules() ([]detect.Rule, error) {
	var rules []detect.Rule
	for i, d := range c.Dictionary {
		values := append([]string(nil), d.Values...)
		if d.File != "" {
			fromFile, err := readLines(expandHome(d.File))
			if err != nil {
				return nil, fmt.Errorf("dictionary %d: %w", i, err)
			}
			values = append(values, fromFile...)
		}
		kind := d.Kind
		if kind == "" {
			kind = "TERM"
		}
		r, err := detect.DictionaryRule(fmt.Sprintf("dictionary[%d]", i), kind, values, d.CaseInsensitive)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
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

// readLines reads one value per line; blank lines and # comments are skipped.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[1:])
		}
	}
	return p
}
