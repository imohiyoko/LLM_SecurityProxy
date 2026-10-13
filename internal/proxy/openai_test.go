package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

// quoted needs escaping inside JSON text: restored into OpenAI "arguments",
// which are JSON in a string, it must not break them.
const quoted = `pa"ss\word-1234`

// openaiFixture stores quoted, so the known-value pass masks it in requests,
// and returns the placeholders the upstream received for secret and quoted.
func openaiFixture(t *testing.T, respond func(w http.ResponseWriter, phSecret, phQuoted string)) *fixture {
	t.Helper()
	var f *fixture
	f = newFixture(t, func(w http.ResponseWriter, body []byte) {
		phs := placeholder.Pattern.FindAllString(string(body), -1)
		var phSecret, phQuoted string
		for _, ph := range phs {
			id := placeholder.Pattern.FindStringSubmatch(ph)[2]
			switch v, _ := f.store.Resolve(id); v {
			case quoted:
				phQuoted = ph
			default:
				phSecret = ph
			}
		}
		respond(w, phSecret, phQuoted)
	})
	if _, _, err := f.store.Put("SECRET", quoted); err != nil {
		t.Fatal(err)
	}
	return f
}

func post(t *testing.T, url string, body any) string {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

// sseData returns the data of each event, JSON-decoded, or the raw string.
func sseData(t *testing.T, stream string) []any {
	t.Helper()
	var out []any
	for _, ev := range strings.Split(stream, "\n\n") {
		for _, l := range strings.Split(ev, "\n") {
			d, ok := strings.CutPrefix(l, "data: ")
			if !ok {
				continue
			}
			var v any
			if json.Unmarshal([]byte(d), &v) != nil {
				v = d
			}
			out = append(out, v)
		}
	}
	return out
}

func writeSSE(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		var m map[string]any
		if json.Unmarshal([]byte(e), &m) == nil && m["type"] != nil {
			fmt.Fprintf(w, "event: %s\n", m["type"])
		}
		fmt.Fprintf(w, "data: %s\n\n", e)
	}
}

func esc(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

func TestChatCompletionStreamUnmasked(t *testing.T) {
	secret := testsecret.AWSAccessKey()
	f := openaiFixture(t, func(w http.ResponseWriter, ph, phq string) {
		// arguments are JSON text, so a placeholder sits inside a JSON string.
		args := `{"cmd":"echo ` + phq + `"}`
		writeSSE(w,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"use `+ph[:9]+`"}}]}`,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"`+ph[9:]+` now `+ph[:5]+`"}}]}`,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"`+ph[5:]+`","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"`+esc(args[:15])+`"}}]}}]}`,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"`+esc(args[15:])+`"}}]}}]}`,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
			`[DONE]`,
		)
	})
	out := post(t, f.proxy.URL+"/v1/chat/completions", map[string]any{
		"model": "m", "stream": true,
		"messages": []any{map[string]any{"role": "user", "content": "use " + secret + " and " + quoted}},
	})

	sent := string(<-f.received)
	if strings.Contains(sent, secret) || strings.Contains(sent, esc(quoted)) {
		t.Fatalf("request not masked: %s", sent)
	}
	var req struct{ Messages []map[string]any }
	json.Unmarshal([]byte(sent), &req)
	if req.Messages[0]["role"] != "system" || req.Messages[0]["content"] != Notice {
		t.Fatalf("notice not the first message: %s", sent)
	}

	var content, args string
	events := sseData(t, out)
	for _, e := range events {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		delta := m["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
		c, _ := delta["content"].(string)
		content += c
		calls, _ := delta["tool_calls"].([]any)
		for _, tc := range calls {
			args += tc.(map[string]any)["function"].(map[string]any)["arguments"].(string)
		}
	}
	if want := "use " + secret + " now " + secret; content != want {
		t.Errorf("content = %q, want %q", content, want)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(args), &parsed); err != nil || parsed["cmd"] != "echo "+quoted {
		t.Errorf("arguments = %q (%v), want cmd %q", args, err, "echo "+quoted)
	}
	if last := events[len(events)-1]; last != "[DONE]" {
		t.Errorf("last event = %v, want [DONE]", last)
	}
}

// A placeholder held back at the end of a stream without finish_reason is
// still emitted, before [DONE].
func TestChatCompletionStreamFlushedAtDone(t *testing.T) {
	secret := testsecret.AWSAccessKey()
	f := openaiFixture(t, func(w http.ResponseWriter, ph, _ string) {
		writeSSE(w,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"x `+ph[:12]+`"}}]}`,
			`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"`+ph[12:]+`"}}]}`,
			`[DONE]`,
		)
	})
	out := post(t, f.proxy.URL+"/v1/chat/completions", map[string]any{
		"model": "m", "stream": true, "messages": []any{map[string]any{"role": "user", "content": secret}},
	})
	var content string
	events := sseData(t, out)
	for _, e := range events {
		if m, ok := e.(map[string]any); ok {
			c, _ := m["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["content"].(string)
			content += c
		}
	}
	if content != "x "+secret || events[len(events)-1] != "[DONE]" {
		t.Errorf("content = %q, events = %v", content, events)
	}
}

func TestResponsesStreamUnmasked(t *testing.T) {
	secret := testsecret.GitHubToken()
	f := openaiFixture(t, func(w http.ResponseWriter, ph, phq string) {
		args := `{"cmd":"echo ` + phq + `"}`
		item := `{"type":"function_call","id":"fc_1","call_id":"call_1","name":"bash","arguments":"` + esc(args) + `"}`
		writeSSE(w,
			`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"use `+ph[:10]+`","sequence_number":1}`,
			`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"`+ph[10:]+` ok `+ph[:6]+`","sequence_number":2}`,
			`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"`+ph[6:20]+`","sequence_number":3}`,
			`{"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"use `+ph+` ok `+ph[:20]+`","sequence_number":4}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"`+esc(args[:16])+`","sequence_number":5}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"`+esc(args[16:])+`","sequence_number":6}`,
			`{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":1,"arguments":"`+esc(args)+`","sequence_number":7}`,
			`{"type":"response.output_item.done","output_index":1,"item":`+item+`,"sequence_number":8}`,
			`{"type":"response.output_item.done","output_index":2,"item":{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"`+ph+`"}]},"sequence_number":9}`,
			`{"type":"response.completed","response":{"id":"r1","output":[`+item+`]},"sequence_number":10}`,
		)
	})
	out := post(t, f.proxy.URL+"/v1/responses", map[string]any{
		"model": "m", "stream": true,
		"input": []any{map[string]any{"type": "message", "role": "user",
			"content": []any{map[string]any{"type": "input_text", "text": secret + " " + quoted}}}},
	})

	var text, args, doneText, doneArgs string
	var items []map[string]any
	for _, e := range sseData(t, out) {
		m := e.(map[string]any)
		switch m["type"] {
		case "response.output_text.delta":
			text += m["delta"].(string)
		case "response.output_text.done":
			doneText = m["text"].(string)
		case "response.function_call_arguments.delta":
			args += m["delta"].(string)
		case "response.function_call_arguments.done":
			doneArgs = m["arguments"].(string)
		case "response.output_item.done":
			items = append(items, m["item"].(map[string]any))
		case "response.completed":
			items = append(items, m["response"].(map[string]any)["output"].([]any)[0].(map[string]any))
		}
	}
	// The last delta ends in a partial placeholder, held back until done
	// and then emitted as it was.
	ph := placeholder.Pattern.FindString(string(<-f.received))
	if want := "use " + secret + " ok " + ph[:20]; text != want || doneText != want {
		t.Errorf("text = %q, done = %q, want %q", text, doneText, want)
	}
	for _, a := range []string{args, doneArgs, items[0]["arguments"].(string), items[2]["arguments"].(string)} {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(a), &parsed); err != nil || parsed["cmd"] != "echo "+quoted {
			t.Errorf("arguments = %q (%v), want cmd %q", a, err, "echo "+quoted)
		}
	}
	if s := items[1]["summary"].([]any)[0].(map[string]any)["text"]; s == secret {
		t.Errorf("reasoning item rewritten: %v", items[1])
	}
}

func TestChatCompletionJSONArgumentsEscaped(t *testing.T) {
	f := openaiFixture(t, func(w http.ResponseWriter, _, phq string) {
		w.Header().Set("Content-Type", "application/json")
		args := `{"cmd":"echo ` + phq + `"}`
		fmt.Fprint(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"`+phq+`",`+
			`"tool_calls":[{"id":"call_1","type":"function","function":{"name":"bash","arguments":"`+esc(args)+`"}}]}}]}`)
	})
	out := post(t, f.proxy.URL+"/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": quoted}},
	})
	var resp struct {
		Choices []struct {
			Message struct {
				Content   string
				ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatal(err)
	}
	msg := resp.Choices[0].Message
	var parsed map[string]string
	if err := json.Unmarshal([]byte(msg.ToolCalls[0].Function.Arguments), &parsed); err != nil || parsed["cmd"] != "echo "+quoted {
		t.Errorf("arguments = %q (%v)", msg.ToolCalls[0].Function.Arguments, err)
	}
	if msg.Content != quoted {
		t.Errorf("content = %q, want %q", msg.Content, quoted)
	}
}
