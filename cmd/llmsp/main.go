// Command llmsp is a local proxy that masks sensitive values before they
// reach an LLM API and restores them in the response.
//
//	llmsp [serve] [-config PATH] [-profile NAME] [-listen ADDR]
//	                                              run the proxy (one listener per profile)
//	llmsp profiles [-config PATH]                 list the listeners, routes and their rules
//	llmsp relax [-config PATH] [-for DURATION] PROFILE
//	                                              serve stricter profiles' requests with PROFILE for a while
//	llmsp relax [-config PATH] -off               end it now
//	llmsp relax [-config PATH]                    show the relaxation in effect
//	llmsp rules list [-config PATH] [-profile NAME]
//	                                              show rulesets and rules
//	llmsp rules test [-config PATH] [-profile NAME] [FILE]
//	                                              show what would be masked
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/proxy"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/relax"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/route"
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
	case "profiles":
		return profiles(args)
	case "relax":
		return relaxCmd(args)
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

func selection(ep config.Endpoint) rules.Selection {
	return rules.Selection{Enable: ep.Enable, Disable: ep.Disable}
}

// masking compiles an endpoint's rules and allowlist.
func (e *env) masking(ep config.Endpoint) (*detect.Detector, []*regexp.Regexp, error) {
	compiled, err := e.catalog.Compile(selection(ep))
	if err != nil {
		return nil, nil, fmt.Errorf("profile %s: %w", ep.Name, err)
	}
	allow, err := ep.AllowPatterns()
	if err != nil {
		return nil, nil, fmt.Errorf("profile %s: %w", ep.Name, err)
	}
	return detect.New(compiled), allow, nil
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
	endpoints, err := cfg.Select(profile, listen)
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
	// One store for all profiles: a value masked for one client gets the same
	// placeholder for another, and restoring stays scoped to the request that
	// issued it. A value once masked for any profile is masked by exact match
	// in every profile, whatever its own rules. Each profile has its own rules.
	named := len(cfg.Profiles) > 0 || len(cfg.Routes) > 0
	// A profile reached by several routes, or also listening itself, is one
	// handler.
	handlers := map[string]*proxy.Server{}
	handler := func(ep config.Endpoint) (*proxy.Server, error) {
		if h, ok := handlers[ep.Name]; ok {
			return h, nil
		}
		det, allow, err := e.masking(ep)
		if err != nil {
			return nil, err
		}
		upstream, err := url.Parse(ep.Upstream.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("profile %s: upstream.base_url: %w", ep.Name, err)
		}
		client, err := newClient(ep.Upstream)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		plog := log
		if named {
			plog = log.With("profile", ep.Name)
		}
		h := &proxy.Server{
			Upstream:     upstream,
			Client:       client,
			Masker:       mask.New(det, st, allow),
			Resolver:     st,
			AuthHeaders:  ep.Upstream.AuthHeaders,
			InjectNotice: ep.InjectNotice,
			Log:          plog,
			Profile:      ep.Name,
			Health:       st.Check,
		}
		handlers[ep.Name] = h
		plog.Info("profile ready", "upstream", upstream.String(), "rules", len(det.Rules()))
		return h, nil
	}
	for _, ep := range endpoints {
		if err := checkLoopback(ep.Listen, cfg.AllowNonLoopback); err != nil {
			return fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		fallback, err := handler(ep)
		if err != nil {
			return err
		}
		var h http.Handler = fallback
		if len(ep.Routes) > 0 {
			rt := &route.Router{Fallback: fallback, FallbackProfile: ep.Name, Log: log}
			for _, r := range ep.Routes {
				rule, err := route.Compile(r.Route)
				if err != nil {
					return fmt.Errorf("route to %s: %w", r.Profile, err)
				}
				target, err := handler(r.Endpoint)
				if err != nil {
					return err
				}
				rt.Targets = append(rt.Targets, route.Target{Rule: rule, Profile: r.Profile, Handler: target})
			}
			// Profiles that may stand in for stricter ones for a while.
			for _, name := range slices.Sorted(maps.Keys(cfg.Profiles)) {
				x := cfg.Profiles[name].Relax
				if x == nil {
					continue
				}
				target, err := handler(cfg.Endpoint(name))
				if err != nil {
					return err
				}
				if rt.Relaxed == nil {
					rt.Relaxed = map[string]route.Relaxed{}
					rt.Relax = &relax.Watcher{
						Path:  relax.Path(cfg.DataDir),
						Limit: cfg.RelaxLimit,
						Changed: func(_ relax.State, _ bool, err error) {
							if err != nil {
								log.Error("relax state unreadable; strict profiles stay in force", "err", err)
							}
						},
					}
				}
				rt.Relaxed[name] = route.Relaxed{Replaces: x.Replaces, Handler: target}
			}
			h = rt
		}
		ln, err := net.Listen("tcp", ep.Listen)
		if err != nil {
			return fmt.Errorf("profile %s: %w", ep.Name, err)
		}
		listeners = append(listeners, ln)
		servers = append(servers, &http.Server{Handler: h})
		log.Info("llmsp listening", "addr", ep.Listen, "profile", ep.Name,
			"routes", len(ep.Routes), "data_dir", cfg.DataDir)
	}

	// The first listener to fail stops the process; a supervisor restarts it.
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	return <-errc
}

// profiles lists what serve would listen on, with the number of rules each
// listener applies. Nothing is started.
func profiles(args []string) error {
	e, err := load("profiles", args, nil)
	if err != nil {
		return err
	}
	endpoints, err := e.cfg.Endpoints()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tLISTEN\tRULES\tALLOWLIST\tROUTE")
	row := func(ep config.Endpoint, listen, how string) error {
		det, allow, err := e.masking(ep)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", ep.Name, listen, len(det.Rules()), len(allow), how)
		return nil
	}
	for _, ep := range endpoints {
		// Routed profiles first, in matching order, then what is left.
		for _, r := range ep.Routes {
			if err := row(r.Endpoint, ep.Listen, describe(r.Route)); err != nil {
				return err
			}
		}
		how := "-"
		if len(ep.Routes) > 0 {
			how = "(no route matched)"
		}
		if err := row(ep, ep.Listen, how); err != nil {
			return err
		}
		if len(ep.Routes) == 0 {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(e.cfg.Profiles)) {
			if x := e.cfg.Profiles[name].Relax; x != nil {
				how := fmt.Sprintf("relax for %s (default %s, max %s)", strings.Join(x.Replaces, ","), x.Default, x.Max)
				if err := row(e.cfg.Endpoint(name), ep.Listen, how); err != nil {
					return err
				}
			}
		}
	}
	return w.Flush()
}

// relaxCmd starts, ends or shows the temporary relaxation. The running
// proxy picks it up within a second and ends it on time by itself.
func relaxCmd(args []string) error {
	var dur time.Duration
	var off bool
	e, err := load("relax", args, func(fs *flag.FlagSet) {
		fs.DurationVar(&dur, "for", 0, "how long (default: the profile's relax.default)")
		fs.BoolVar(&off, "off", false, "end the relaxation now")
	})
	if err != nil {
		return err
	}
	cfg := e.cfg
	path := relax.Path(cfg.DataDir)
	now := time.Now()
	switch name := e.flags.Arg(0); {
	case off:
		if name != "" || e.flags.NArg() > 1 {
			return errors.New("relax -off takes no profile")
		}
		if err := relax.Clear(path); err != nil {
			return err
		}
		fmt.Println("not relaxed: strict profiles in force")
		return nil
	case name == "":
		s, ok, err := relax.Load(path)
		if err != nil {
			return err
		}
		if !ok || !relax.Valid(s, now, cfg.RelaxLimit) {
			fmt.Println("not relaxed")
			return nil
		}
		fmt.Printf("relaxed %s until %s (%s left)\n", s.Profile, s.Until.Local().Format(time.RFC3339),
			s.Until.Sub(now).Round(time.Minute))
		return nil
	default:
		if e.flags.NArg() > 1 {
			return errors.New("put -for before the profile: llmsp relax -for 2h PROFILE")
		}
		p, ok := cfg.Profiles[name]
		if !ok || p.Relax == nil {
			return fmt.Errorf("profile %s has no relax settings in the config", name)
		}
		if dur == 0 {
			dur = p.Relax.Default
		}
		if dur <= 0 || dur > p.Relax.Max {
			return fmt.Errorf("profile %s may be relaxed to for up to %s", name, p.Relax.Max)
		}
		s := relax.State{Profile: name, Since: now.UTC(), Until: now.Add(dur).UTC()}
		if err := relax.Save(path, s); err != nil {
			return err
		}
		fmt.Printf("relaxed %s until %s, for requests of %s\n", name, s.Until.Local().Format(time.RFC3339),
			strings.Join(p.Relax.Replaces, ", "))
		return nil
	}
}

// describe is a route's conditions, for display.
func describe(r config.Route) string {
	var parts []string
	if r.Client != "" {
		parts = append(parts, "client="+r.Client)
	}
	for _, name := range slices.Sorted(maps.Keys(r.Header)) {
		parts = append(parts, fmt.Sprintf("header %s=~%q", name, r.Header[name]))
	}
	if r.PathPrefix != "" {
		parts = append(parts, "path="+r.PathPrefix)
	}
	if len(parts) == 0 {
		return "(any)"
	}
	return strings.Join(parts, " ")
}

// loadMasking loads the config and the masking settings of -profile.
func loadMasking(name string, args []string) (*env, config.Endpoint, error) {
	var profile string
	e, err := load(name, args, func(fs *flag.FlagSet) {
		fs.StringVar(&profile, "profile", "", "use this profile's rules (default: the top-level ones)")
	})
	if err != nil {
		return nil, config.Endpoint{}, err
	}
	ep, err := e.cfg.Masking(profile)
	return e, ep, err
}

func rulesList(args []string) error {
	e, ep, err := loadMasking("rules list", args)
	if err != nil {
		return err
	}
	states, err := e.catalog.Resolve(selection(ep))
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
	e, ep, err := loadMasking("rules test", args)
	if err != nil {
		return err
	}
	det, allow, err := e.masking(ep)
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
