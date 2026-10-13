// Command llmsp is a local proxy that masks sensitive values before they
// reach an LLM API and restores them in the response.
//
//	llmsp [serve] [-config PATH] [-profile NAME] [-listen ADDR]
//	                                              run the proxy (one listener per profile)
//	llmsp rules list [-config PATH]               show rulesets and rules
//	llmsp rules test [-config PATH] [FILE]        show what would be masked
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/proxy"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "llmsp:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve(args)
	case "rules":
		if len(args) == 0 {
			return errors.New("usage: llmsp rules list|test")
		}
		switch args[0] {
		case "list":
			return rulesList(args[1:])
		case "test":
			return rulesTest(args[1:])
		}
		return fmt.Errorf("unknown rules command %q", args[0])
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// env is the loaded configuration shared by all commands.
type env struct {
	cfg     *config.Config
	catalog *rules.Catalog
	flags   *flag.FlagSet
}

func load(name string, args []string, extra func(*flag.FlagSet)) (*env, error) {
	dir, err := config.DefaultDir()
	if err != nil {
		return nil, err
	}
	defaultPath := filepath.Join(dir, "config.yaml")
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("config", defaultPath, "path to config.yaml")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg, err := config.Load(*cfgPath, *cfgPath != defaultPath)
	if err != nil {
		return nil, err
	}
	catalog, err := rules.Load(cfg.RuleDirs(filepath.Dir(*cfgPath)))
	if err != nil {
		return nil, err
	}
	return &env{cfg: cfg, catalog: catalog, flags: fs}, nil
}

func (e *env) selection() rules.Selection {
	return rules.Selection{Enable: e.cfg.Rulesets.Enable, Disable: e.cfg.Rulesets.Disable}
}

func (e *env) detector() (*detect.Detector, error) {
	compiled, err := e.catalog.Compile(e.selection())
	if err != nil {
		return nil, err
	}
	return detect.New(compiled), nil
}

func serve(args []string) error {
	var listen, profile string
	e, err := load("serve", args, func(fs *flag.FlagSet) {
		fs.StringVar(&listen, "listen", "", "listen address (overrides config; with profiles, only with -profile)")
		fs.StringVar(&profile, "profile", "", "serve only this profile")
	})
	if err != nil {
		return err
	}
	cfg := e.cfg
	if listen != "" && len(cfg.Profiles) == 0 {
		cfg.Listen = listen
	}
	endpoints, err := cfg.Endpoints()
	if err != nil {
		return err
	}
	if profile != "" {
		i := slices.IndexFunc(endpoints, func(ep config.Endpoint) bool { return ep.Name == profile })
		if len(cfg.Profiles) == 0 || i < 0 {
			return fmt.Errorf("-profile %s: no such profile in the config", profile)
		}
		endpoints = endpoints[i : i+1]
	}
	if listen != "" && len(cfg.Profiles) > 0 {
		if profile == "" {
			return errors.New("-listen with profiles needs -profile: it sets the listen address of one profile")
		}
		endpoints[0].Listen = listen
	}
	det, err := e.detector()
	if err != nil {
		return err
	}
	allow, err := cfg.AllowPatterns()
	if err != nil {
		return err
	}

	// Set up every listener before serving any, so a bad profile fails startup.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var servers []*http.Server
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	// One masker and store for all profiles: a value masked for one client
	// gets the same placeholder for another, and restoring stays scoped to
	// the request that issued it.
	masker := mask.New(det, st, allow)
	for _, ep := range endpoints {
		if err := checkLoopback(ep.Listen, cfg.AllowNonLoopback); err != nil {
			return fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		upstream, err := url.Parse(ep.Upstream.BaseURL)
		if err != nil {
			return fmt.Errorf("profile %s: upstream.base_url: %w", ep.Name, err)
		}
		client, err := newClient(ep.Upstream)
		if err != nil {
			return fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		plog := log
		if len(cfg.Profiles) > 0 {
			plog = log.With("profile", ep.Name)
		}
		srv := &proxy.Server{
			Upstream:     upstream,
			Client:       client,
			Masker:       masker,
			Resolver:     st,
			AuthHeaders:  ep.Upstream.AuthHeaders,
			InjectNotice: ep.InjectNotice,
			Log:          plog,
			Profile:      ep.Name,
			Health:       st.Ping,
		}
		ln, err := net.Listen("tcp", ep.Listen)
		if err != nil {
			return fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		listeners = append(listeners, ln)
		servers = append(servers, &http.Server{Handler: srv})
		plog.Info("llmsp listening", "addr", ep.Listen, "upstream", upstream.String(),
			"data_dir", cfg.DataDir, "rules", len(det.Rules()))
	}

	// The first listener to fail stops the process; a supervisor restarts it.
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	return <-errc
}

func rulesList(args []string) error {
	e, err := load("rules list", args, nil)
	if err != nil {
		return err
	}
	states, err := e.catalog.Resolve(e.selection())
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tRULE\tKIND\tSOURCE")
	for _, s := range states {
		state := "off"
		if s.On {
			state = "on"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", state, rules.FullID(s.Set.ID, s.Spec.ID), s.Spec.Kind, s.Set.Source)
	}
	return w.Flush()
}

// rulesTest prints what the enabled rules match in a file or stdin. Nothing is
// stored and nothing is sent anywhere.
func rulesTest(args []string) error {
	e, err := load("rules test", args, nil)
	if err != nil {
		return err
	}
	det, err := e.detector()
	if err != nil {
		return err
	}
	allow, err := e.cfg.AllowPatterns()
	if err != nil {
		return err
	}
	var in io.Reader = os.Stdin
	if f := e.flags.Arg(0); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		defer fh.Close()
		in = fh
	}
	b, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	text := string(b)
	matches := det.Find(text)
	sort.Slice(matches, func(i, j int) bool { return matches[i].Start < matches[j].Start })
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "LINE\tRULE\tKIND\tVALUE")
	for _, m := range matches {
		v := text[m.Start:m.End]
		rule := m.Rule
		for _, a := range allow {
			if a.MatchString(v) {
				rule += " (allowlisted)"
				break
			}
		}
		line := strings.Count(text[:m.Start], "\n") + 1
		fmt.Fprintf(w, "%d\t%s\t%s\t%q\n", line, rule, m.Kind, v)
	}
	return w.Flush()
}

// checkLoopback refuses non-local listeners: anyone who can reach the proxy
// can read restored values in its responses.
func checkLoopback(listen string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) || allowNonLoopback {
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
