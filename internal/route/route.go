// Package route picks the profile that serves a request on a routing
// listener.
//
// Clients are recognised by headers they send:
//
//   - claude-code: X-Claude-Code-Session-Id, documented in Claude Code's LLM
//     gateway protocol.
//   - codex: an Originator header starting with "codex", which the Codex CLI
//     sets on every request (codex_cli_rs, codex_vscode, ...).
//   - cline: X-Title: Cline, which Cline sends to its own API.
//
// Cline sends no such header to other providers; route it by a header of
// your own or a path prefix instead.
package route

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/proxy"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/relax"
)

// HeaderPrefix marks headers meant for llmsp. They are removed from every
// request before it is forwarded, matched or not.
const HeaderPrefix = "X-Llmsp-"

type cond struct {
	header string
	re     *regexp.Regexp // nil: the header only has to be present
}

// clients: any one condition identifies the client.
var clients = map[string][]cond{
	"claude-code": {{"X-Claude-Code-Session-Id", nil}},
	"codex":       {{"Originator", regexp.MustCompile(`^codex`)}},
	"cline":       {{"X-Title", regexp.MustCompile(`^Cline$`)}},
}

// Rule is a compiled route.
type Rule struct {
	client []cond
	header []cond
	prefix string
}

// Compile compiles a route. The config has already been validated.
func Compile(r config.Route) (*Rule, error) {
	out := &Rule{prefix: r.PathPrefix}
	if r.Client != "" {
		c, ok := clients[r.Client]
		if !ok {
			return nil, fmt.Errorf("unknown client %q", r.Client)
		}
		out.client = c
	}
	for name, pat := range r.Header {
		c := cond{header: http.CanonicalHeaderKey(name)}
		if pat != "" {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("header %s: %w", name, err)
			}
			c.re = re
		}
		out.header = append(out.header, c)
	}
	return out, nil
}

func (c cond) holds(h http.Header) bool {
	vs := h.Values(c.header)
	if len(vs) == 0 {
		return false
	}
	if c.re == nil {
		return vs[0] != ""
	}
	for _, v := range vs {
		if c.re.MatchString(v) {
			return true
		}
	}
	return false
}

// Match reports whether r matches.
func (rule *Rule) Match(r *http.Request) bool {
	if rule.prefix != "" {
		p := r.URL.Path
		if p != rule.prefix && !strings.HasPrefix(p, rule.prefix+"/") {
			return false
		}
	}
	for _, c := range rule.header {
		if !c.holds(r.Header) {
			return false
		}
	}
	if len(rule.client) > 0 {
		any := false
		for _, c := range rule.client {
			any = any || c.holds(r.Header)
		}
		if !any {
			return false
		}
	}
	return true
}

// Target is a compiled route and the profile it sends requests to.
type Target struct {
	Rule    *Rule
	Profile string
	Handler http.Handler
}

// Relaxed is a profile that may serve, for a while, the requests routed to
// the profiles it Replaces.
type Relaxed struct {
	Replaces []string
	Handler  http.Handler
}

// Router sends each request to the first target whose rule matches, or to
// Fallback. llmsp's own headers are removed and a matched path prefix is
// cut off first.
type Router struct {
	Targets  []Target
	Fallback http.Handler
	// FallbackProfile names Fallback ("default").
	FallbackProfile string

	// Relax, if set, says which relaxation is in effect; Relaxed are the
	// profiles it may name.
	Relax   *relax.Watcher
	Relaxed map[string]Relaxed
	Log     *slog.Logger

	mu      sync.Mutex
	current string // relaxed profile in effect at the last request, for logging
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next, prefix, profile := rt.Fallback, "", rt.FallbackProfile
	for _, t := range rt.Targets {
		if t.Rule.Match(r) {
			next, prefix, profile = t.Handler, t.Rule.prefix, t.Profile
			break
		}
	}
	if s, ok := rt.relaxed(time.Now()); ok {
		if x := rt.Relaxed[s.Profile]; slices.Contains(x.Replaces, profile) {
			next = x.Handler
			r = r.WithContext(proxy.WithLogAttrs(r.Context(), "relaxed_from", profile, "relaxed_until", s.Until.Format(time.RFC3339)))
		}
	}
	r = r.Clone(r.Context())
	for name := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), HeaderPrefix) {
			r.Header.Del(name)
		}
	}
	if prefix != "" {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		r.URL.RawPath = ""
	}
	next.ServeHTTP(w, r)
}

// relaxed is the relaxation in effect, logging when it starts and ends.
func (rt *Router) relaxed(now time.Time) (relax.State, bool) {
	if rt.Relax == nil {
		return relax.State{}, false
	}
	s, ok := rt.Relax.Active(now)
	name := ""
	if ok {
		name = s.Profile
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if name != rt.current && rt.Log != nil {
		if name != "" {
			rt.Log.Warn("relaxed: requests of stricter profiles use a looser one", "profile", name, "until", s.Until.Format(time.RFC3339))
		} else {
			rt.Log.Info("relaxation ended: strict profiles in force again", "profile", rt.current)
		}
	}
	rt.current = name
	return s, ok
}
