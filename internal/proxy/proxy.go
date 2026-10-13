// Package proxy is the HTTP reverse proxy that masks requests and unmasks
// responses.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// MaxBodyBytes bounds request and non-streamed response bodies.
const MaxBodyBytes = 64 << 20

// Notice tells the model what placeholders are and how to use them.
const Notice = "Some sensitive values in this conversation were replaced by a local privacy proxy " +
	"with placeholders of the form __LLMSP_<KIND>_<id>__. Treat each placeholder as an opaque stand-in " +
	"for the real value. Whenever the value is needed (in code, commands, file edits or replies), write " +
	"the placeholder exactly as it appears, character for character; the proxy restores the real value " +
	"locally. Do not guess, alter, split, re-case, encode or ask for the real values."

// Server is an http.Handler.
type Server struct {
	Upstream *url.URL
	Client   *http.Client
	Masker   *mask.Masker
	// Resolver looks up placeholder values. A response only restores the
	// placeholders issued while masking its own request.
	Resolver unmask.Resolver
	// AuthHeaders are forwarded unmasked: they carry the upstream credential.
	// Every other header value is masked.
	AuthHeaders  []string
	InjectNotice bool
	Log          *slog.Logger
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := s.Log.With("method", r.Method, "path", r.URL.Path)

	body, stats, ids, err := s.maskRequest(r)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			log.Warn("request rejected", "status", he.status, "reason", he.msg)
			writeError(w, he.status, he.msg)
			return
		}
		log.Error("mask failed", "err", err)
		writeError(w, http.StatusInternalServerError, "llmsp: masking failed; request not forwarded")
		return
	}

	query, err := s.maskQuery(r.URL.RawQuery, stats, ids)
	if err != nil {
		log.Warn("request rejected", "status", http.StatusBadRequest, "reason", "bad query")
		writeError(w, http.StatusBadRequest, "llmsp: malformed query string")
		return
	}

	target := *s.Upstream
	target.Path = strings.TrimSuffix(s.Upstream.Path, "/") + r.URL.Path
	target.RawQuery = query

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	if err := s.maskHeader(out.Header, stats, ids); err != nil {
		log.Error("mask failed", "err", err)
		writeError(w, http.StatusInternalServerError, "llmsp: masking failed; request not forwarded")
		return
	}
	// Let the transport negotiate gzip and decompress, so we can read bodies.
	out.Header.Del("Accept-Encoding")
	out.Header.Del("Content-Length")
	out.ContentLength = int64(len(body))
	if len(body) == 0 {
		out.Body = http.NoBody
	}

	resp, err := s.Client.Do(out)
	if err != nil {
		log.Error("upstream failed", "err", err)
		writeError(w, http.StatusBadGateway, "llmsp: upstream request failed")
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		if slices.Contains(hopHeaders, k) || k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}

	res := scoped{s.Resolver, ids}
	ct := resp.Header.Get("Content-Type")
	var restored int
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		w.WriteHeader(resp.StatusCode)
		restored, err = streamSSE(w, resp.Body, res)
	case strings.HasPrefix(ct, "application/json"):
		restored, err = unmaskJSON(w, resp, res)
	default:
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
	}
	attrs := []any{"status", resp.StatusCode, "masked", statsAttr(stats), "restored", restored}
	if err != nil {
		log.Error("response failed", append(attrs, "err", err)...)
		return
	}
	log.Info("proxied", attrs...)
}

type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

// scoped resolves only the IDs issued while masking one request.
type scoped struct {
	r   unmask.Resolver
	ids mask.IDs
}

func (s scoped) Resolve(id string) (string, bool) {
	if !s.ids[id] {
		return "", false
	}
	return s.r.Resolve(id)
}

func (s *Server) maskRequest(r *http.Request) ([]byte, mask.Stats, mask.IDs, error) {
	stats, ids := mask.Stats{}, mask.IDs{}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(raw) > MaxBodyBytes {
		return nil, nil, nil, &httpError{http.StatusRequestEntityTooLarge, "llmsp: request body too large"}
	}
	if len(raw) == 0 {
		return raw, stats, ids, nil
	}
	// Fail closed: anything we cannot inspect is not forwarded.
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return nil, nil, nil, &httpError{http.StatusUnsupportedMediaType, "llmsp: compressed request bodies are not supported"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, nil, &httpError{http.StatusUnsupportedMediaType, "llmsp: request body must be JSON"}
	}
	if dec.More() {
		return nil, nil, nil, &httpError{http.StatusUnsupportedMediaType, "llmsp: request body must be a single JSON value"}
	}

	doc, err = maskStrings(doc,
		func(v string) (string, error) { return s.Masker.String(v, stats, ids) },
		func(k, v string) (string, error) { return s.Masker.Field(k, v, stats, ids) })
	if err != nil {
		return nil, nil, nil, err
	}
	if m, ok := doc.(map[string]any); ok && s.InjectNotice {
		switch {
		case isAnthropicMessages(r.URL.Path):
			injectSystemNotice(m)
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			injectChatNotice(m)
		case strings.HasSuffix(r.URL.Path, "/responses"):
			injectResponsesNotice(m)
		}
	}
	out, err := marshal(doc)
	return out, stats, ids, err
}

// maskHeader masks every header value except the upstream credential.
func (s *Server) maskHeader(h http.Header, stats mask.Stats, ids mask.IDs) error {
	for k, vs := range h {
		if slices.ContainsFunc(s.AuthHeaders, func(a string) bool { return strings.EqualFold(a, k) }) {
			continue
		}
		// X-User-Name names the same field as User-Name.
		name := k
		if len(name) > 2 && strings.EqualFold(name[:2], "X-") {
			name = name[2:]
		}
		for i, v := range vs {
			out, err := s.Masker.Field(name, v, stats, ids)
			if err != nil {
				return err
			}
			vs[i] = out
		}
	}
	return nil
}

// maskQuery masks query keys and values. An unchanged query is forwarded
// byte for byte.
func (s *Server) maskQuery(raw string, stats mask.Stats, ids mask.IDs) (string, error) {
	if raw == "" {
		return raw, nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", err
	}
	masked := url.Values{}
	changed := false
	for k, vs := range q {
		mk, err := s.Masker.String(k, stats, ids)
		if err != nil {
			return "", err
		}
		for _, v := range vs {
			mv, err := s.Masker.Field(k, v, stats, ids)
			if err != nil {
				return "", err
			}
			masked.Add(mk, mv)
			changed = changed || mv != v
		}
		changed = changed || mk != k
	}
	if !changed {
		return raw, nil
	}
	return masked.Encode(), nil
}

func isAnthropicMessages(path string) bool {
	return strings.HasSuffix(path, "/v1/messages") || strings.HasSuffix(path, "/v1/messages/count_tokens")
}

// injectSystemNotice appends the notice to the Anthropic system prompt. It is
// appended (not prepended) so cached prefixes set by the client stay intact,
// and added on every request so the prompt does not change between turns.
func injectSystemNotice(m map[string]any) {
	switch sys := m["system"].(type) {
	case nil:
		m["system"] = Notice
	case string:
		m["system"] = sys + "\n\n" + Notice
	case []any:
		m["system"] = append(sys, map[string]any{"type": "text", "text": Notice})
	}
}

// injectChatNotice adds the notice to the leading system or developer
// message of an OpenAI chat completion, or puts a system message first.
func injectChatNotice(m map[string]any) {
	msgs, ok := m["messages"].([]any)
	if !ok {
		return
	}
	if first, ok := firstInstructions(msgs); ok {
		switch c := first["content"].(type) {
		case string:
			first["content"] = c + "\n\n" + Notice
			return
		case []any:
			first["content"] = append(c, map[string]any{"type": "text", "text": Notice})
			return
		}
	}
	m["messages"] = append([]any{map[string]any{"role": "system", "content": Notice}}, msgs...)
}

func firstInstructions(msgs []any) (map[string]any, bool) {
	if len(msgs) == 0 {
		return nil, false
	}
	first, ok := msgs[0].(map[string]any)
	if !ok || (first["role"] != "system" && first["role"] != "developer") {
		return nil, false
	}
	return first, true
}

// injectResponsesNotice puts the notice first in the input of an OpenAI
// Responses API request, as a developer message. instructions is left alone:
// some backends accept only the client's own instructions there.
func injectResponsesNotice(m map[string]any) {
	switch in := m["input"].(type) {
	case []any:
		note := map[string]any{
			"type":    "message",
			"role":    "developer",
			"content": []any{map[string]any{"type": "input_text", "text": Notice}},
		}
		m["input"] = append([]any{note}, in...)
	case string:
		m["input"] = []any{
			map[string]any{"role": "developer", "content": Notice},
			map[string]any{"role": "user", "content": in},
		}
	}
}

func unmaskJSON(w http.ResponseWriter, resp *http.Response, res unmask.Resolver) (int, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		w.WriteHeader(resp.StatusCode)
		_, err = w.Write(raw)
		return 0, err
	}
	doc, total := restoreStrings(doc, res)
	out, err := marshal(doc)
	if err != nil {
		return 0, err
	}
	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(out)
	return total, err
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": "llmsp_error", "message": msg},
	})
	w.Write(b)
}

func statsAttr(st mask.Stats) string {
	if len(st) == 0 {
		return "none"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(st)) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, st[k]))
	}
	return strings.Join(parts, ",")
}
