package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// skipKeys hold protocol fields, not conversation content. Masking them would
// break the request (IDs, signatures) or waste work (base64 media). They are
// only honoured at the protocol level, never inside tool arguments.
var skipKeys = map[string]bool{
	"type":              true,
	"id":                true,
	"tool_use_id":       true,
	"call_id":           true,
	"name":              true,
	"model":             true,
	"role":              true,
	"signature":         true,
	"media_type":        true,
	"data":              true,
	"cache_control":     true,
	"stop_reason":       true,
	"metadata":          true,
	"encrypted_content": true,
}

// toolArgs reports whether m[k] holds tool arguments: arbitrary user data,
// where everything below is content whatever the key names are. "input" only
// counts inside a tool-use block; the OpenAI Responses API also uses it at the
// top level for the whole conversation, which keeps its protocol fields.
func toolArgs(k string, m map[string]any) bool {
	switch k {
	case "input":
		switch m["type"] {
		case "tool_use", "server_tool_use", "mcp_tool_use":
			return true
		}
	case "arguments": // OpenAI function calls
		return true
	}
	return false
}

// opaqueBlock reports whether a content block must be passed through byte for
// byte. Thinking blocks are signed by the server; editing them is rejected.
func opaqueBlock(m map[string]any) bool {
	switch m["type"] {
	case "thinking", "redacted_thinking", "reasoning":
		return true
	}
	return false
}

// walkStrings applies fn to every content string in v, in place. Object keys
// inside tool arguments are content too: a streamed tool input is restored as
// raw JSON, keys included, so the request side must mask them as well or a
// restored key would be resent upstream in plaintext on the next turn.
//
// If a restored key would collide with another key of the same object, the
// key is kept as it was, so no member is dropped.
func walkStrings(v any, fn func(string) (string, error)) (any, error) {
	return walk(v, fn, nil, nil, false, false)
}

// restoreStrings is walkStrings for responses: it restores placeholders in
// every content string and returns how many it restored. An OpenAI
// "arguments" member is JSON text inside a string, so values restored into it
// are JSON-escaped; a value with a quote or a backslash would otherwise break
// the arguments the client parses.
func restoreStrings(v any, res unmask.Resolver) (any, int) {
	n := 0
	with := func(esc unmask.Escaper) func(string) (string, error) {
		return func(s string) (string, error) {
			out, c := unmask.Replace(s, res, esc)
			n += c
			return out, nil
		}
	}
	v, _ = walk(v, with(unmask.Identity), nil, with(unmask.JSONString), false, false)
	return v, n
}

// maskStrings is walkStrings for the request side, where a key that should be
// masked is never forwarded as is: a masked key that would collide gets a
// " (n)" suffix instead (see rekey). A string member of an object inside
// tool arguments is passed to field with its key instead of to fn, so that
// it can be masked by its field name.
func maskStrings(v any, fn func(string) (string, error), field func(key, value string) (string, error)) (any, error) {
	return walk(v, fn, field, nil, false, true)
}

// args, if set, is applied instead of fn to a protocol-level string
// "arguments" member (not one inside tool arguments, which is plain data).
func walk(v any, fn func(string) (string, error), field func(key, value string) (string, error), args func(string) (string, error), free, strict bool) (any, error) {
	switch t := v.(type) {
	case string:
		return fn(t)
	case []any:
		for i, e := range t {
			nv, err := walk(e, fn, field, args, free, strict)
			if err != nil {
				return nil, err
			}
			t[i] = nv
		}
		return t, nil
	case map[string]any:
		if !free && opaqueBlock(t) {
			return t, nil
		}
		for k, e := range t {
			if !free && skipKeys[k] && !textData(k, t) {
				continue
			}
			var nv any
			var err error
			str, isStr := e.(string)
			switch {
			case isStr && free && field != nil:
				nv, err = field(k, str)
			case isStr && !free && k == "arguments" && args != nil:
				nv, err = args(str)
			case isStr && !free && k == "arguments" && field != nil:
				nv, err = maskArguments(str, fn, field)
			default:
				nv, err = walk(e, fn, field, args, free || toolArgs(k, t), strict)
			}
			if err != nil {
				return nil, err
			}
			t[k] = nv
		}
		if free {
			if err := rekey(t, fn, strict); err != nil {
				return nil, err
			}
		}
		return t, nil
	default:
		return v, nil
	}
}

// rekey applies fn to the keys of m. Keys are visited in sorted order, and a
// new key may not take the name of any original key or of an earlier
// rewritten one, so the result does not depend on map iteration order.
//
// A colliding key is kept as it was, unless strict: then it is renamed to the
// new key plus " (2)", " (3)", ..., the first free one. The secret is not sent,
// no member is dropped, and the same input always gives the same result, so a
// client resending it as history every turn is not rejected every turn.
func rekey(m map[string]any, fn func(string) (string, error), strict bool) error {
	keys := slices.Sorted(maps.Keys(m))
	taken := map[string]bool{}
	free := func(k string) bool {
		_, orig := m[k]
		return !orig && !taken[k]
	}
	type move struct{ from, to string }
	var moves []move
	for _, k := range keys {
		nk, err := fn(k)
		if err != nil {
			return err
		}
		if nk == k {
			continue
		}
		if !free(nk) {
			if !strict {
				continue
			}
			base := nk
			for n := 2; !free(nk); n++ {
				nk = fmt.Sprintf("%s (%d)", base, n)
			}
		}
		taken[nk] = true
		moves = append(moves, move{k, nk})
	}
	vals := make([]any, len(moves))
	for i, mv := range moves {
		vals[i] = m[mv.from]
		delete(m, mv.from)
	}
	for i, mv := range moves {
		m[mv.to] = vals[i]
	}
	return nil
}

// textData reports a plain-text document source ({"media_type":"text/plain",
// "data":"..."}), whose data is content rather than base64.
func textData(key string, m map[string]any) bool {
	if key != "data" {
		return false
	}
	mt, _ := m["media_type"].(string)
	return strings.HasPrefix(mt, "text/")
}

// maskArguments masks OpenAI function call arguments, JSON source in a
// string. A value restored into them was JSON-escaped (a quote as \"), and
// the client sends the arguments back verbatim on the next turn, so the
// values are matched decoded: the escaped form of a known value would not
// match it. Arguments are re-encoded only if something in them was masked.
// Arguments that are not JSON are masked as text.
func maskArguments(raw string, fn func(string) (string, error), field func(key, value string) (string, error)) (string, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return fn(raw)
	}
	before, err := marshal(v)
	if err != nil {
		return fn(raw)
	}
	masked, err := walk(v, fn, field, nil, true, true)
	if err != nil {
		return "", err
	}
	after, err := marshal(masked)
	if err != nil {
		return "", err
	}
	if bytes.Equal(before, after) {
		return fn(raw)
	}
	return fn(string(after))
}
