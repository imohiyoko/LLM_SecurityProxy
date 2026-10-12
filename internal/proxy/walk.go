package proxy

import (
	"errors"
	"maps"
	"slices"
	"strings"
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

// freeKeys hold arbitrary user data (tool arguments). Everything below them is
// content, whatever the key names are.
var freeKeys = map[string]bool{
	"input":     true, // Anthropic tool_use
	"arguments": true, // OpenAI function calls
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
// If a rewritten key would collide with another key of the same object, the
// key is kept as it was, so no member is dropped.
func walkStrings(v any, fn func(string) (string, error)) (any, error) {
	return walk(v, fn, false, false)
}

// maskStrings is walkStrings for the request side: a key collision is an
// error, so a key that should be masked is never forwarded as is.
func maskStrings(v any, fn func(string) (string, error)) (any, error) {
	return walk(v, fn, false, true)
}

var errKeyCollision = errors.New("proxy: masked object key collides with another key")

func walk(v any, fn func(string) (string, error), free, strict bool) (any, error) {
	switch t := v.(type) {
	case string:
		return fn(t)
	case []any:
		for i, e := range t {
			nv, err := walk(e, fn, free, strict)
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
			nv, err := walk(e, fn, free || freeKeys[k], strict)
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
func rekey(m map[string]any, fn func(string) (string, error), strict bool) error {
	keys := slices.Sorted(maps.Keys(m))
	taken := map[string]bool{}
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
		if _, orig := m[nk]; orig || taken[nk] {
			if strict {
				return errKeyCollision
			}
			continue
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
