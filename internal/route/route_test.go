package route

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/config"
)

func TestClientsMatchConfig(t *testing.T) {
	for _, c := range config.Clients {
		if _, ok := clients[c]; !ok {
			t.Errorf("config accepts client %s, but it is not detected here", c)
		}
	}
	if len(clients) != len(config.Clients) {
		t.Errorf("detected clients %d, config accepts %d", len(clients), len(config.Clients))
	}
}

func req(path string, h map[string]string) *http.Request {
	r := httptest.NewRequest("POST", path, nil)
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func TestMatch(t *testing.T) {
	for name, tc := range map[string]struct {
		route config.Route
		path  string
		h     map[string]string
		want  bool
	}{
		"claude code":         {config.Route{Client: "claude-code"}, "/v1/messages", map[string]string{"X-Claude-Code-Session-Id": "s1"}, true},
		"claude code, no hdr": {config.Route{Client: "claude-code"}, "/v1/messages", map[string]string{"User-Agent": "claude-cli/2"}, false},
		"codex":               {config.Route{Client: "codex"}, "/v1/responses", map[string]string{"Originator": "codex_cli_rs"}, true},
		"codex vscode":        {config.Route{Client: "codex"}, "/v1/responses", map[string]string{"Originator": "codex_vscode"}, true},
		"not codex":           {config.Route{Client: "codex"}, "/v1/responses", map[string]string{"Originator": "cline"}, false},
		"cline":               {config.Route{Client: "cline"}, "/v1/chat/completions", map[string]string{"X-Title": "Cline"}, true},
		"header present":      {config.Route{Header: map[string]string{"x-llmsp-profile": ""}}, "/", map[string]string{"X-Llmsp-Profile": "a"}, true},
		"header absent":       {config.Route{Header: map[string]string{"x-llmsp-profile": ""}}, "/", nil, false},
		"header pattern":      {config.Route{Header: map[string]string{"X-Llmsp-Profile": "^strict$"}}, "/", map[string]string{"X-Llmsp-Profile": "strict"}, true},
		"header pattern miss": {config.Route{Header: map[string]string{"X-Llmsp-Profile": "^strict$"}}, "/", map[string]string{"X-Llmsp-Profile": "strictly"}, false},
		"prefix":              {config.Route{PathPrefix: "/cline"}, "/cline/v1/messages", nil, true},
		"prefix exact":        {config.Route{PathPrefix: "/cline"}, "/cline", nil, true},
		"prefix, longer word": {config.Route{PathPrefix: "/cline"}, "/clinex/v1/messages", nil, false},
		"all conditions hold": {config.Route{Client: "codex", PathPrefix: "/a"}, "/a/v1", map[string]string{"Originator": "codex_cli_rs"}, true},
		"one condition fails": {config.Route{Client: "codex", PathPrefix: "/a"}, "/b/v1", map[string]string{"Originator": "codex_cli_rs"}, false},
		"no conditions":       {config.Route{}, "/anything", nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			rule, err := Compile(tc.route)
			if err != nil {
				t.Fatal(err)
			}
			if got := rule.Match(req(tc.path, tc.h)); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

type seen struct {
	name string
	path string
	hdrs []string
}

func record(name string, into *seen) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*into = seen{name: name, path: r.URL.Path}
		for k := range r.Header {
			into.hdrs = append(into.hdrs, k)
		}
		slices.Sort(into.hdrs)
	})
}

func TestRouter(t *testing.T) {
	var got seen
	compile := func(r config.Route) *Rule {
		rule, err := Compile(r)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	rt := &Router{
		Targets: []Target{
			{compile(config.Route{Header: map[string]string{"X-Llmsp-Profile": "^strict$"}}), record("strict", &got)},
			{compile(config.Route{Client: "claude-code"}), record("claude", &got)},
			{compile(config.Route{PathPrefix: "/cline"}), record("cline", &got)},
		},
		Fallback: record("default", &got),
	}
	for name, tc := range map[string]struct {
		path string
		h    map[string]string
		want seen
	}{
		// The first matching route wins, and X-Llmsp-* is not forwarded.
		"header before client": {"/v1/messages", map[string]string{"X-Llmsp-Profile": "strict", "X-Claude-Code-Session-Id": "s"},
			seen{"strict", "/v1/messages", []string{"X-Claude-Code-Session-Id"}}},
		"client":   {"/v1/messages", map[string]string{"X-Claude-Code-Session-Id": "s"}, seen{"claude", "/v1/messages", []string{"X-Claude-Code-Session-Id"}}},
		"prefix":   {"/cline/v1/messages", nil, seen{"cline", "/v1/messages", nil}},
		"fallback": {"/v1/messages", map[string]string{"X-Llmsp-Profile": "nope"}, seen{"default", "/v1/messages", nil}},
	} {
		t.Run(name, func(t *testing.T) {
			got = seen{}
			rt.ServeHTTP(httptest.NewRecorder(), req(tc.path, tc.h))
			if got.name != tc.want.name || got.path != tc.want.path || !slices.Equal(got.hdrs, tc.want.hdrs) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
