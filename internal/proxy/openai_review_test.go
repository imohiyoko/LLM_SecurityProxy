package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
)

type mapResolver map[string]string

func (m mapResolver) Resolve(id string) (string, bool) { v, ok := m[id]; return v, ok }

const testID = "0123456789ab"

var (
	testPH  = placeholder.Format("SECRET", testID)
	testRes = mapResolver{testID: "s3cr3t-value"}
)

// runSSE streams the given data lines (one event each) through streamSSE.
func runSSE(t *testing.T, named bool, data ...string) (string, int) {
	t.Helper()
	var in strings.Builder
	for _, d := range data {
		var m map[string]any
		if named && json.Unmarshal([]byte(d), &m) == nil {
			fmt.Fprintf(&in, "event: %s\n", m["type"])
		}
		fmt.Fprintf(&in, "data: %s\n\n", d)
	}
	rec := httptest.NewRecorder()
	n, err := streamSSE(rec, strings.NewReader(in.String()), testRes)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Body.String(), n
}

func events(t *testing.T, out string) []map[string]any {
	t.Helper()
	var evs []map[string]any
	for _, d := range sseData(t, out) {
		if m, ok := d.(map[string]any); ok {
			evs = append(evs, m)
		}
	}
	return evs
}

// chatText concatenates a string field of choice 0's deltas, or of its
// tool call deltas when tool is set.
func chatText(t *testing.T, out, field string, tool bool) string {
	var s string
	for _, e := range events(t, out) {
		choices, _ := e["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		delta, _ := choices[0].(map[string]any)["delta"].(map[string]any)
		if !tool {
			v, _ := delta[field].(string)
			s += v
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		for _, c := range calls {
			v, _ := c.(map[string]any)["function"].(map[string]any)["arguments"].(string)
			s += v
		}
	}
	return s
}

// A value restored into arguments is JSON-escaped; the client sends it back
// in that form, and it must still be masked.
func TestRestoredArgumentsMaskedOnNextTurn(t *testing.T) {
	f := openaiFixture(t, func(w http.ResponseWriter, _, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	args := `{"cmd":"login ` + esc(quoted) + `"}`
	for _, tc := range []struct{ path, body string }{
		{"/v1/responses", `{"model":"m","input":[{"type":"function_call","call_id":"c1","name":"bash","arguments":` + jsonStr(args) + `}]}`},
		{"/v1/chat/completions", `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":` + jsonStr(args) + `}}]}]}`},
	} {
		resp, err := http.Post(f.proxy.URL+tc.path, "application/json", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		sent := string(<-f.received)
		var doc any
		json.Unmarshal([]byte(sent), &doc)
		if strings.Contains(fmt.Sprint(doc), quoted) || !placeholder.Pattern.MatchString(sent) {
			t.Errorf("%s: escaped known value not masked: %s", tc.path, sent)
		}
	}
}

// Arguments with nothing to mask are forwarded byte for byte.
func TestUnmaskedArgumentsVerbatim(t *testing.T) {
	f := openaiFixture(t, func(w http.ResponseWriter, _, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	args := `{ "z": 1,  "a": "x<y" }`
	body := `{"model":"m","input":[{"type":"function_call","call_id":"c1","name":"bash","arguments":` + jsonStr(args) + `}]}`
	resp, err := http.Post(f.proxy.URL+"/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var sent struct{ Input []map[string]any }
	raw := <-f.received
	json.Unmarshal(raw, &sent)
	if got := sent.Input[len(sent.Input)-1]["arguments"]; got != args {
		t.Errorf("arguments = %q, want %q", got, args)
	}
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestResponsesNoticeSkippedWhenStateful(t *testing.T) {
	f := openaiFixture(t, func(w http.ResponseWriter, _, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	for _, extra := range []string{`"previous_response_id":"resp_1"`, `"conversation":"conv_1"`} {
		body := `{"model":"m",` + extra + `,"input":[{"type":"message","role":"user","content":"hi"}]}`
		resp, err := http.Post(f.proxy.URL+"/v1/responses", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if sent := string(<-f.received); strings.Contains(sent, "privacy proxy") {
			t.Errorf("%s: notice injected: %s", extra, sent)
		}
	}
}

func TestChatStreamWithoutIndexes(t *testing.T) {
	out, _ := runSSE(t, false,
		`{"choices":[{"delta":{"content":"a `+testPH[:8]+`","tool_calls":[{"function":{"arguments":"{\"k\":\"`+testPH[:5]+`"}}]}}]}`,
		`{"choices":[{"delta":{"content":"`+testPH[8:]+`","tool_calls":[{"function":{"arguments":"`+testPH[5:]+`\"}"}}]},"finish_reason":"stop"}]}`,
		`[DONE]`)
	if got := chatText(t, out, "content", false); got != "a s3cr3t-value" {
		t.Errorf("content = %q", got)
	}
	if got := chatText(t, out, "", true); got != `{"k":"s3cr3t-value"}` {
		t.Errorf("arguments = %q", got)
	}
}

func TestChatStreamFlushedAtEOF(t *testing.T) {
	// The stream ends in what could be the start of a placeholder: held
	// back, it must still be sent when the stream ends without [DONE].
	out, _ := runSSE(t, false, `{"id":"c","choices":[{"index":0,"delta":{"content":"x `+testPH[:10]+`"}}]}`,
		`{"id":"c","choices":[{"index":0,"delta":{"content":"`+testPH[10:]+` `+testPH[:20]+`"}}]}`)
	if got := chatText(t, out, "content", false); got != "x s3cr3t-value "+testPH[:20] {
		t.Errorf("content = %q", got)
	}
}

func TestChatStreamRefusalAndLegacyFunctionCall(t *testing.T) {
	out, _ := runSSE(t, false,
		`{"choices":[{"index":0,"delta":{"refusal":"no `+testPH[:9]+`","function_call":{"name":"f","arguments":"{\"k\":\"`+testPH[:9]+`"}}}]}`,
		`{"choices":[{"index":0,"delta":{"refusal":"`+testPH[9:]+`","function_call":{"arguments":"`+testPH[9:]+`\"}"}},"finish_reason":"stop"}]}`)
	if got := chatText(t, out, "refusal", false); got != "no s3cr3t-value" {
		t.Errorf("refusal = %q", got)
	}
	var args string
	for _, e := range events(t, out) {
		fc, _ := e["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["function_call"].(map[string]any)
		a, _ := fc["arguments"].(string)
		args += a
	}
	if args != `{"k":"s3cr3t-value"}` {
		t.Errorf("function_call.arguments = %q", args)
	}
}

// Text held by several tool calls at finish is appended in index order.
func TestChatStreamFlushOrder(t *testing.T) {
	for range 20 {
		out, _ := runSSE(t, false,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"`+testPH[:6]+`"}},{"index":1,"function":{"arguments":"`+testPH[:6]+`"}},{"index":2,"function":{"arguments":"`+testPH[:6]+`"}}]}}]}`,
			`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
		evs := events(t, out)
		calls := evs[len(evs)-1]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)
		for i, c := range calls {
			if c.(map[string]any)["index"] != float64(i) {
				t.Fatalf("flushed tool calls out of order: %v", calls)
			}
		}
	}
}

// An event with nothing to restore is passed through byte for byte.
func TestUnchangedEventsVerbatim(t *testing.T) {
	chunk := `{"id":"c", "created":1.70e9,"choices":[{"index":0,"delta":{"content":"plain"}}]}`
	resp := `{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"plain", "sequence_number":3}`
	for _, d := range []string{chunk, resp} {
		if out, _ := runSSE(t, false, d); out != "data: "+d+"\n\n" {
			t.Errorf("rewritten:\n got %q\nwant %q", out, "data: "+d+"\n\n")
		}
	}
}

func TestResponsesStreamEndsWithoutDone(t *testing.T) {
	out, _ := runSSE(t, true,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"x `+testPH[:10]+`","sequence_number":1}`,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"`+testPH[10:20]+`","sequence_number":2}`,
		`{"type":"response.incomplete","response":{"id":"r"},"sequence_number":3}`)
	var text string
	evs := events(t, out)
	for _, e := range evs {
		if e["type"] == "response.output_text.delta" {
			text += e["delta"].(string)
		}
	}
	if text != "x "+testPH[:20] || evs[len(evs)-1]["type"] != "response.incomplete" {
		t.Errorf("text = %q, events = %v", text, evs)
	}
}

func TestResponsesMCPArguments(t *testing.T) {
	out, _ := runSSE(t, true,
		`{"type":"response.mcp_call_arguments.delta","item_id":"mc","output_index":0,"delta":"{\"k\":\"`+testPH[:7]+`","sequence_number":1}`,
		`{"type":"response.mcp_call_arguments.delta","item_id":"mc","output_index":0,"delta":"`+testPH[7:]+`\"}","sequence_number":2}`,
		`{"type":"response.mcp_call_arguments.done","item_id":"mc","output_index":0,"arguments":"{\"k\":\"`+testPH+`\"}","sequence_number":3}`)
	var args, done string
	for _, e := range events(t, out) {
		switch e["type"] {
		case "response.mcp_call_arguments.delta":
			args += e["delta"].(string)
		case "response.mcp_call_arguments.done":
			done = e["arguments"].(string)
		}
	}
	if want := `{"k":"s3cr3t-value"}`; args != want || done != want {
		t.Errorf("args = %q, done = %q", args, done)
	}
}

// sequence_number stays consecutive though a held delta is dropped and a
// flush delta is added.
func TestResponsesSequenceNumbers(t *testing.T) {
	out, _ := runSSE(t, true,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"`+testPH[:10]+`","sequence_number":10}`,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"`+testPH[10:20]+`","sequence_number":11}`,
		`{"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":0,"text":"`+testPH[:20]+`","sequence_number":12}`,
		`{"type":"response.completed","response":{"id":"r"},"sequence_number":13}`)
	evs := events(t, out)
	for i, e := range evs {
		if e["sequence_number"] != float64(10+i) {
			t.Fatalf("event %d has sequence_number %v: %v", i, e["sequence_number"], evs)
		}
	}
}

// Reasoning summaries are left masked everywhere: the client sends reasoning
// items back and the request side does not mask them.
func TestResponsesReasoningLeftAlone(t *testing.T) {
	part := `{"type":"summary_text","text":"` + testPH + `"}`
	in := []string{
		`{"type":"response.reasoning_summary_part.added","item_id":"rs","output_index":0,"summary_index":0,"part":` + part + `,"sequence_number":1}`,
		`{"type":"response.reasoning_summary_text.delta","item_id":"rs","output_index":0,"summary_index":0,"delta":"` + testPH + `","sequence_number":2}`,
		`{"type":"response.reasoning_summary_part.done","item_id":"rs","output_index":0,"summary_index":0,"part":` + part + `,"sequence_number":3}`,
	}
	out, n := runSSE(t, false, in...)
	if want := "data: " + strings.Join(in, "\n\ndata: ") + "\n\n"; out != want || n != 0 {
		t.Errorf("reasoning rewritten (restored=%d):\n%s", n, out)
	}
}

// One placeholder seen in a delta, the done event, the item and the final
// response is counted once.
func TestResponsesRestoredCount(t *testing.T) {
	item := `{"type":"message","id":"m","content":[{"type":"output_text","text":"` + testPH + `"}]}`
	_, n := runSSE(t, true,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"`+testPH+`","sequence_number":1}`,
		`{"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":0,"text":"`+testPH+`","sequence_number":2}`,
		`{"type":"response.output_item.done","output_index":0,"item":`+item+`,"sequence_number":3}`,
		`{"type":"response.completed","response":{"id":"r","output":[`+item+`]},"sequence_number":4}`)
	if n != 1 {
		t.Errorf("restored = %d, want 1", n)
	}
}

// Arguments that are not JSON (a model can produce those) are masked as
// text; a known value in them is found in its escaped form too, and its
// placeholder stands for the escaped text it replaced.
func TestInvalidJSONArgumentsMasked(t *testing.T) {
	f := openaiFixture(t, func(w http.ResponseWriter, _, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	args := `{"cmd":"login ` + esc(quoted) // truncated: not JSON
	body := `{"model":"m","input":[{"type":"function_call","call_id":"c1","name":"bash","arguments":` + jsonStr(args) + `}]}`
	resp, err := http.Post(f.proxy.URL+"/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var sent struct{ Input []map[string]any }
	json.Unmarshal(<-f.received, &sent)
	got := sent.Input[len(sent.Input)-1]["arguments"].(string)
	ph := placeholder.Pattern.FindStringSubmatch(got)
	if strings.Contains(got, esc(quoted)) || ph == nil {
		t.Fatalf("arguments = %q", got)
	}
	if v, _ := f.store.Resolve(ph[2]); v != esc(quoted) {
		t.Errorf("placeholder stands for %q, want %q", v, esc(quoted))
	}
}

// A done event without the content_index its deltas had still closes their
// stream: the held tail goes out before it, not again after it.
func TestResponsesDoneWithoutContentIndex(t *testing.T) {
	out, _ := runSSE(t, true,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"a `+testPH[:20]+`","sequence_number":1}`,
		`{"type":"response.output_text.done","item_id":"m","output_index":0,"text":"a `+testPH[:20]+`","sequence_number":2}`,
		`{"type":"response.completed","response":{"id":"r"},"sequence_number":3}`)
	var types []any
	var text string
	for _, e := range events(t, out) {
		types = append(types, e["type"])
		if e["type"] == "response.output_text.delta" {
			text += e["delta"].(string)
		}
	}
	if text != "a "+testPH[:20] || types[len(types)-2] != "response.output_text.done" {
		t.Errorf("text = %q, events = %v", text, types)
	}
}

// Tool calls without an index, one per chunk, all sit at position 0; a held
// tail of one call is not prepended to the next.
func TestChatStreamToolCallsWithoutIndexSeparate(t *testing.T) {
	out, _ := runSSE(t, false,
		`{"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"name":"f","arguments":"{\"x\":1} __LL"}}]}}]}`,
		`{"choices":[{"delta":{"tool_calls":[{"id":"b","function":{"name":"g","arguments":"{\"y\":1}"}}]}}]}`,
		`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`)
	args := map[string]string{}
	var last string
	for _, e := range events(t, out) {
		delta := e["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
		calls, _ := delta["tool_calls"].([]any)
		for _, c := range calls {
			call := c.(map[string]any)
			if id, ok := call["id"].(string); ok {
				last = id
			}
			a, _ := call["function"].(map[string]any)["arguments"].(string)
			args[last] += a
		}
	}
	if args["a"] != `{"x":1} __LL` || args["b"] != `{"y":1}` {
		t.Errorf("arguments = %q", args)
	}
}

// A done event without deltas is not matched to another content index's
// finished stream: its own restoration is counted.
func TestResponsesDoneFallbackSkipsClosedStreams(t *testing.T) {
	_, n := runSSE(t, true,
		`{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"plain","sequence_number":1}`,
		`{"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":0,"text":"plain","sequence_number":2}`,
		`{"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":1,"text":"`+testPH+`","sequence_number":3}`)
	if n != 1 {
		t.Errorf("restored = %d, want 1", n)
	}
}

// A known value matched in its escaped form, here in a string literal in
// plain text, is restored as it was written, escapes included.
func TestEscapedKnownValueRoundTrip(t *testing.T) {
	// The placeholder stands for the escaped text, not for quoted, so the
	// fixture passes it as the first one.
	f := openaiFixture(t, func(w http.ResponseWriter, ph, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"`+esc(`echo "`)+ph+esc(`"`)+`"}}]}`)
	})
	cmd := `echo "` + esc(quoted) + `"`
	out := post(t, f.proxy.URL+"/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": "run " + cmd}},
	})
	if sent := string(<-f.received); strings.Contains(sent, esc(esc(quoted))) {
		t.Fatalf("escaped value not masked: %s", sent)
	}
	var resp struct {
		Choices []struct{ Message struct{ Content string } }
	}
	json.Unmarshal([]byte(out), &resp)
	if got := resp.Choices[0].Message.Content; got != cmd {
		t.Errorf("content = %q, want %q", got, cmd)
	}
}
