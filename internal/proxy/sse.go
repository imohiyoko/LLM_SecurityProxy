package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// sseState tracks one streamed response: an Anthropic message, an OpenAI
// chat completion or an OpenAI Responses API response. The formats do not
// share event shapes, so one state handles all three.
type sseState struct {
	res    unmask.Resolver
	blocks map[int]*blockState

	// OpenAI Chat Completions: one stream per choice content and per tool
	// call's arguments. last is the latest chunk, the template for a chunk
	// that flushes what is still held when the stream ends.
	chat     map[chatKey]*unmask.Stream
	chatLast map[string]any

	// OpenAI Responses API: one stream per delta source, by event key.
	resp map[string]*unmask.Stream

	// restored outside streams: full values in done events and items.
	extra int
}

// chatKey: tool is -1 for the message content.
type chatKey struct{ choice, tool int }

type blockState struct {
	deltaType string // "text_delta" or "input_json_delta"
	field     string // "text" or "partial_json"
	stream    *unmask.Stream
}

// streamSSE rewrites an Anthropic Messages event stream, restoring
// placeholders in text and tool input deltas. Thinking deltas are left as is:
// thinking blocks are signed and come back verbatim in the next request.
func streamSSE(w http.ResponseWriter, body io.Reader, res unmask.Resolver) (int, error) {
	st := &sseState{res: res, blocks: map[int]*blockState{}, chat: map[chatKey]*unmask.Stream{}, resp: map[string]*unmask.Stream{}}
	flusher, _ := w.(http.Flusher)
	r := bufio.NewReaderSize(body, 64<<10)
	var event [][]byte
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) == 0 {
				if werr := st.writeEvent(w, event); werr != nil {
					return st.count(), werr
				}
				event = nil
				if flusher != nil {
					flusher.Flush()
				}
			} else {
				event = append(event, append([]byte(nil), trimmed...))
			}
		}
		if err == io.EOF {
			if len(event) > 0 {
				if werr := st.writeEvent(w, event); werr != nil {
					return st.count(), werr
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
			return st.count(), nil
		}
		if err != nil {
			return st.count(), err
		}
	}
}

func (st *sseState) count() int {
	n := st.extra
	for _, b := range st.blocks {
		n += b.stream.Count
	}
	for _, s := range st.chat {
		n += s.Count
	}
	for _, s := range st.resp {
		n += s.Count
	}
	return n
}

// writeEvent processes one event (its lines, without the blank terminator).
func (st *sseState) writeEvent(w io.Writer, lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	var name string
	var data []byte
	for _, l := range lines {
		switch {
		case bytes.HasPrefix(l, []byte("event:")):
			name = string(bytes.TrimSpace(l[len("event:"):]))
		case bytes.HasPrefix(l, []byte("data:")):
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(l[len("data:"):], []byte(" "))...)
		}
	}
	var msg map[string]any
	if data == nil || json.Unmarshal(data, &msg) != nil {
		if string(data) == "[DONE]" { // end of an OpenAI chat stream
			if err := st.flushChat(w); err != nil {
				return err
			}
		}
		return writeRaw(w, lines)
	}
	if _, ok := msg["choices"].([]any); ok {
		return st.chatChunk(w, name, msg)
	}
	if t, _ := msg["type"].(string); strings.HasPrefix(t, "response.") {
		return st.responsesEvent(w, lines, name, t, msg)
	}

	switch msg["type"] {
	case "content_block_start":
		idx, ok := index(msg)
		cb, _ := msg["content_block"].(map[string]any)
		if !ok || cb == nil {
			break
		}
		switch cb["type"] {
		case "text":
			st.blocks[idx] = &blockState{"text_delta", "text", unmask.NewStream(st.res, unmask.Identity)}
		case "tool_use", "server_tool_use":
			st.blocks[idx] = &blockState{"input_json_delta", "partial_json", unmask.NewStream(st.res, unmask.JSONString)}
		}
		if !opaqueBlock(cb) {
			walkStrings(cb, func(v string) (string, error) {
				out, _ := unmask.Replace(v, st.res, unmask.Identity)
				return out, nil
			})
		}
		return writeJSON(w, name, msg)

	case "content_block_delta":
		idx, ok := index(msg)
		delta, _ := msg["delta"].(map[string]any)
		b := st.blocks[idx]
		if !ok || delta == nil || b == nil || delta["type"] != b.deltaType {
			break
		}
		text, _ := delta[b.field].(string)
		out := b.stream.Write(text)
		if out == "" && text != "" {
			return nil // held back; emitted with a later delta
		}
		delta[b.field] = out
		return writeJSON(w, name, msg)

	case "content_block_stop":
		idx, ok := index(msg)
		b := st.blocks[idx]
		if !ok || b == nil {
			break
		}
		if rest := b.stream.Flush(); rest != "" {
			flush := map[string]any{
				"type":  "content_block_delta",
				"index": msg["index"],
				"delta": map[string]any{"type": b.deltaType, b.field: rest},
			}
			if err := writeJSON(w, "content_block_delta", flush); err != nil {
				return err
			}
		}
		return writeRaw(w, lines)
	}
	return writeRaw(w, lines)
}

func index(msg map[string]any) (int, bool) {
	f, ok := msg["index"].(float64)
	return int(f), ok
}

func writeRaw(w io.Writer, lines [][]byte) error {
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}

func writeJSON(w io.Writer, name string, msg map[string]any) error {
	b, err := marshal(msg)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if name != "" {
		buf.WriteString("event: " + name + "\n")
	}
	buf.WriteString("data: ")
	buf.Write(b)
	buf.WriteString("\n\n")
	_, err = w.Write(buf.Bytes())
	return err
}

// chatChunk restores an OpenAI chat.completion.chunk: choices[].delta.content
// and the arguments of choices[].delta.tool_calls[]. When a choice finishes,
// what its streams still hold is added to the same chunk, before the client
// reads finish_reason.
func (st *sseState) chatChunk(w io.Writer, name string, msg map[string]any) error {
	st.chatLast = msg
	choices, _ := msg["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		ci, ok := index(choice)
		if !ok {
			continue
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			delta = map[string]any{}
		}
		if text, ok := delta["content"].(string); ok {
			delta["content"] = st.chatStream(chatKey{ci, -1}, unmask.Identity).Write(text)
		}
		calls, _ := delta["tool_calls"].([]any)
		for _, tc := range calls {
			call, _ := tc.(map[string]any)
			ti, ok := index(call)
			fn, _ := call["function"].(map[string]any)
			if !ok || fn == nil {
				continue
			}
			if args, ok := fn["arguments"].(string); ok {
				fn["arguments"] = st.chatStream(chatKey{ci, ti}, unmask.JSONString).Write(args)
			}
		}
		if choice["finish_reason"] != nil {
			st.flushChoice(ci, delta)
		}
		if len(delta) > 0 {
			choice["delta"] = delta
		}
	}
	return writeJSON(w, name, msg)
}

func (st *sseState) chatStream(k chatKey, esc unmask.Escaper) *unmask.Stream {
	s := st.chat[k]
	if s == nil {
		s = unmask.NewStream(st.res, esc)
		st.chat[k] = s
	}
	return s
}

// flushChoice appends what choice ci still holds to delta.
func (st *sseState) flushChoice(ci int, delta map[string]any) {
	for k, s := range st.chat {
		if k.choice != ci {
			continue
		}
		rest := s.Flush()
		if rest == "" {
			continue
		}
		if k.tool < 0 {
			text, _ := delta["content"].(string)
			delta["content"] = text + rest
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		delta["tool_calls"] = append(calls, map[string]any{
			"index":    k.tool,
			"function": map[string]any{"arguments": rest},
		})
	}
}

// flushChat emits, before [DONE], what choices that never finished still hold.
func (st *sseState) flushChat(w io.Writer) error {
	var choices []any
	seen := map[int]bool{}
	for k := range st.chat {
		if seen[k.choice] {
			continue
		}
		seen[k.choice] = true
		delta := map[string]any{}
		st.flushChoice(k.choice, delta)
		if len(delta) > 0 {
			choices = append(choices, map[string]any{"index": k.choice, "delta": delta})
		}
	}
	if len(choices) == 0 {
		return nil
	}
	chunk := map[string]any{}
	for _, k := range []string{"id", "object", "created", "model"} {
		if v, ok := st.chatLast[k]; ok {
			chunk[k] = v
		}
	}
	chunk["choices"] = choices
	return writeJSON(w, "", chunk)
}

// responsesDelta describes a Responses API delta event and its done event.
type responsesDelta struct {
	done  string         // the matching done event type
	field string         // where the done event carries the full value
	esc   unmask.Escaper // how a restored value is written into the value
}

var responsesDeltas = map[string]responsesDelta{
	"response.output_text.delta":             {"response.output_text.done", "text", unmask.Identity},
	"response.refusal.delta":                 {"response.refusal.done", "refusal", unmask.Identity},
	"response.function_call_arguments.delta": {"response.function_call_arguments.done", "arguments", unmask.JSONString},
	"response.custom_tool_call_input.delta":  {"response.custom_tool_call_input.done", "input", unmask.Identity},
}

// responsesEvent restores an OpenAI Responses API event. Deltas go through a
// stream that holds back a partial placeholder; the done event first gets
// what is still held as one more delta, then its full value restored. Items,
// content parts and the final response are restored whole; reasoning items
// are left as they are.
func (st *sseState) responsesEvent(w io.Writer, lines [][]byte, name, typ string, msg map[string]any) error {
	if d, ok := responsesDeltas[typ]; ok {
		text, _ := msg["delta"].(string)
		k := responsesKey(typ, msg)
		s := st.resp[k]
		if s == nil {
			s = unmask.NewStream(st.res, d.esc)
			st.resp[k] = s
		}
		out := s.Write(text)
		if out == "" && text != "" {
			return nil // held back; emitted with a later delta
		}
		msg["delta"] = out
		return writeJSON(w, name, msg)
	}
	for dtyp, d := range responsesDeltas {
		if d.done != typ {
			continue
		}
		if s := st.resp[responsesKey(dtyp, msg)]; s != nil {
			if rest := s.Flush(); rest != "" {
				flush := map[string]any{"type": dtyp, "delta": rest}
				for _, f := range []string{"item_id", "output_index", "content_index", "sequence_number"} {
					if v, ok := msg[f]; ok {
						flush[f] = v
					}
				}
				evname := ""
				if name != "" {
					evname = dtyp
				}
				if err := writeJSON(w, evname, flush); err != nil {
					return err
				}
			}
		}
		if v, ok := msg[d.field].(string); ok {
			out, n := unmask.Replace(v, st.res, d.esc)
			msg[d.field] = out
			st.extra += n
		}
		return writeJSON(w, name, msg)
	}
	changed := false
	for _, f := range []string{"item", "part", "response"} {
		if v, ok := msg[f]; ok {
			nv, n := restoreStrings(v, st.res)
			msg[f] = nv
			st.extra += n
			changed = changed || n > 0
		}
	}
	if !changed {
		return writeRaw(w, lines)
	}
	return writeJSON(w, name, msg)
}

// responsesKey identifies the value a delta event belongs to.
func responsesKey(typ string, msg map[string]any) string {
	return fmt.Sprintf("%s|%v|%v|%v", typ, msg["item_id"], msg["output_index"], msg["content_index"])
}
