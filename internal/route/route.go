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
	"net/http"
	"regexp"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
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

// Target is a compiled route and the handler it sends requests to.
type Target struct {
	Rule    *Rule
	Handler http.Handler
}

// Router sends each request to the first target whose rule matches, or to
// Fallback. llmsp's own headers are removed and a matched path prefix is
// cut off first.
type Router struct {
	Targets  []Target
	Fallback http.Handler
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next, prefix := rt.Fallback, ""
	for _, t := range rt.Targets {
		if t.Rule.Match(r) {
			next, prefix = t.Handler, t.Rule.prefix
			break
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
