package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/mask"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/rules"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

type fixture struct {
	proxy    *httptest.Server
	store    *store.Store
	received chan []byte
}

// newFixture starts a fake upstream that records request bodies and replies
// with respond(body).
func newFixture(t *testing.T, respond func(w http.ResponseWriter, body []byte)) *fixture {
	t.Helper()
	f := &fixture{received: make(chan []byte, 4)}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.received <- b
		respond(w, b)
	}))
	t.Cleanup(up.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.store = st
	det, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(up.URL)
	srv := &Server{
		Upstream:     u,
		Client:       up.Client(),
		Masker:       mask.New(det, st, nil),
		Resolver:     st,
		InjectNotice: true,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	f.proxy = httptest.NewServer(srv)
	t.Cleanup(f.proxy.Close)
	return f
}

func requestBody(secret string) string {
	return fmt.Sprintf(`{
	"model": "claude-test",
	"stream": true,
	"system": [{"type": "text", "text": "You are helpful."}],
	"messages": [
		{"role": "user", "content": "deploy with %[1]s"},
		{"role": "assistant", "content": [
			{"type": "thinking", "thinking": "keep %[1]s verbatim", "signature": "sig"},
			{"type": "tool_use", "id": "tu_1", "name": "write", "input": {"name": "%[1]s", "path": "a.txt"}}
		]},
		{"role": "user", "content": [
			{"type": "tool_result", "tool_use_id": "tu_1", "content": [{"type": "text", "text": "cat: %[1]s"}]}
		]}
	]
}`, secret)
}

func TestRequestMaskedAndStreamUnmasked(t *testing.T) {
	secret := testsecret.AWSAccessKey()
	f := newFixture(t, func(w http.ResponseWriter, body []byte) {
		ph := placeholder.Pattern.FindString(string(body))
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			`{"type":"message_start","message":{"id":"m","content":[]}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"use %s"}}`, ph[:7]),
			fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"%s"}}`, ph[7:20]),
			fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"%s now"}}`, ph[20:]),
			`{"type":"content_block_stop","index":0}`,
			`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_2","name":"bash","input":{}}}`,
			fmt.Sprintf(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\": \"echo %s"}}`, ph[:10]),
			fmt.Sprintf(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"%s\"}"}}`, ph[10:]),
			`{"type":"content_block_stop","index":1}`,
			`{"type":"message_stop"}`,
		}
		for _, e := range events {
			var m map[string]any
			json.Unmarshal([]byte(e), &m)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m["type"], e)
		}
	})

	resp, err := http.Post(f.proxy.URL+"/v1/messages", "application/json", strings.NewReader(requestBody(secret)))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	sent := <-f.received
	s := string(sent)
	var req map[string]any
	if err := json.Unmarshal(sent, &req); err != nil {
		t.Fatal(err)
	}

	// Thinking is signed: it must reach upstream untouched, secret and all.
	if !strings.Contains(s, `"thinking":"keep `+secret+` verbatim"`) {
		t.Fatalf("thinking block altered: %s", s)
	}
	withoutThinking := strings.Replace(s, "keep "+secret+" verbatim", "", 1)
	if strings.Contains(withoutThinking, secret) {
		t.Fatalf("secret leaked upstream: %s", s)
	}
	if strings.Count(s, "__LLMSP_AWS_ACCESS_KEY_") != 3 {
		t.Fatalf("expected 3 placeholders (user, tool input name, tool result): %s", s)
	}
	sys := req["system"].([]any)
	if last := sys[len(sys)-1].(map[string]any); last["text"] != Notice {
		t.Fatalf("notice not appended: %v", sys)
	}

	// Reassemble the client-visible stream.
	var text, toolJSON strings.Builder
	for _, block := range strings.Split(string(out), "\n\n") {
		_, data, ok := strings.Cut(block, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		json.Unmarshal([]byte(data), &ev)
		text.WriteString(ev.Delta.Text)
		toolJSON.WriteString(ev.Delta.PartialJSON)
	}
	if text.String() != "use "+secret+" now" {
		t.Fatalf("text: %q", text.String())
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(toolJSON.String()), &input); err != nil || input["cmd"] != "echo "+secret {
		t.Fatalf("tool input: %q (%v)", toolJSON.String(), err)
	}
}

func TestJSONResponseUnmasked(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, body []byte) {
		ph := placeholder.Pattern.FindString(string(body))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"content":[{"type":"text","text":"mail %s"},{"type":"thinking","thinking":"%s","signature":"s"}]}`, ph, ph)
	})
	resp, err := http.Post(f.proxy.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"write to bob@corp.dev"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	<-f.received
	out, _ := io.ReadAll(resp.Body)
	var got struct {
		Content []map[string]string `json:"content"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Content[0]["text"] != "mail bob@corp.dev" {
		t.Fatalf("text: %v", got.Content[0])
	}
	if !strings.HasPrefix(got.Content[1]["thinking"], placeholder.Prefix) {
		t.Fatalf("thinking must stay masked: %v", got.Content[1])
	}
}

func TestRejectsUninspectableBodies(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, body []byte) {})
	for name, req := range map[string]func() *http.Request{
		"not json": func() *http.Request {
			r, _ := http.NewRequest("POST", f.proxy.URL+"/v1/messages", strings.NewReader("hello "+testsecret.AWSAccessKey()))
			return r
		},
		"gzip": func() *http.Request {
			r, _ := http.NewRequest("POST", f.proxy.URL+"/v1/messages", strings.NewReader("\x1f\x8b..."))
			r.Header.Set("Content-Encoding", "gzip")
			return r
		},
	} {
		resp, err := http.DefaultClient.Do(req())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
	select {
	case b := <-f.received:
		t.Fatalf("uninspectable body was forwarded: %q", b)
	default:
	}
}
