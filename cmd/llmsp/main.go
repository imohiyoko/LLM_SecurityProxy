// Command llmsp is a local proxy that masks sensitive values before they
// reach an LLM API and restores them in the response.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/proxy"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "llmsp:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := config.DefaultDir()
	if err != nil {
		return err
	}
	defaultPath := filepath.Join(dir, "config.yaml")
	cfgPath := flag.String("config", defaultPath, "path to config.yaml")
	listen := flag.String("listen", "", "listen address (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath, *cfgPath != defaultPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if err := checkLoopback(cfg); err != nil {
		return err
	}

	dict, err := cfg.DictionaryRules()
	if err != nil {
		return err
	}
	det, err := detect.New(cfg.Detectors.Enable, cfg.Detectors.Disable, dict)
	if err != nil {
		return err
	}
	allow, err := cfg.AllowPatterns()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	upstream, err := url.Parse(cfg.Upstream.BaseURL)
	if err != nil {
		return fmt.Errorf("upstream.base_url: %w", err)
	}
	client, err := newClient(cfg.Upstream)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := &proxy.Server{
		Upstream:     upstream,
		Client:       client,
		Masker:       mask.New(det, st, allow),
		Resolver:     st,
		InjectNotice: cfg.Notice(),
		Log:          log,
	}
	log.Info("llmsp listening", "addr", cfg.Listen, "upstream", upstream.String(), "data_dir", cfg.DataDir)
	return (&http.Server{Addr: cfg.Listen, Handler: srv}).ListenAndServe()
}

// checkLoopback refuses non-local listeners: anyone who can reach the proxy
// can read restored values in its responses.
func checkLoopback(cfg *config.Config) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) || cfg.AllowNonLoopback {
		return nil
	}
	return errors.New("listen address is not loopback; set allow_non_loopback: true if you really mean it")
}

func newClient(u config.Upstream) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	if u.Proxy != "" {
		p, err := url.Parse(u.Proxy)
		if err != nil {
			return nil, fmt.Errorf("upstream.proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(p)
	}
	if u.CAFile != "" {
		pem, err := os.ReadFile(u.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream.ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("upstream.ca_file: no certificates found")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	// No overall timeout: streamed responses can run for many minutes.
	return &http.Client{Transport: tr}, nil
}
