package proxy

import "strings"

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

// walkStrings applies fn to every content string in v, in place.
func walkStrings(v any, fn func(string) (string, error)) (any, error) {
	return walk(v, fn, false)
}

func walk(v any, fn func(string) (string, error), free bool) (any, error) {
	switch t := v.(type) {
	case string:
		return fn(t)
	case []any:
		for i, e := range t {
			nv, err := walk(e, fn, free)
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
			nv, err := walk(e, fn, free || freeKeys[k])
			if err != nil {
				return nil, err
			}
			t[k] = nv
		}
		return t, nil
	default:
		return v, nil
	}
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
