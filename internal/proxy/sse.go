package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// sseState tracks one streamed response: an Anthropic message, an OpenAI
// chat completion or an OpenAI Responses API response. The formats do not
// share event shapes, so one state handles all three; chat and resp are
// created on the first event of their format.
type sseState struct {
	res    unmask.Resolver
	blocks map[int]*blockState
	chat   *chatState
	resp   *respState
}

type blockState struct {
	deltaType string // "text_delta" or "input_json_delta"
	field     string // "text" or "partial_json"
	stream    *unmask.Stream
}

// streamSSE rewrites an Anthropic Messages event stream, restoring
// placeholders in text and tool input deltas. Thinking deltas are left as is:
// thinking blocks are signed and come back verbatim in the next request.
func streamSSE(w http.ResponseWriter, body io.Reader, res unmask.Resolver) (int, error) {
	st := &sseState{res: res, blocks: map[int]*blockState{}}
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
			// A stream can end without [DONE] or a done event; what is
			// still held goes out rather than being dropped.
			if werr := st.flushOpenAI(w); werr != nil {
				return st.count(), werr
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
	n := 0
	for _, b := range st.blocks {
		n += b.stream.Count
	}
	if st.chat != nil {
		n += st.chat.count()
	}
	if st.resp != nil {
		n += st.resp.count()
	}
	return n
}

func (st *sseState) flushOpenAI(w io.Writer) error {
	if st.chat != nil {
		if err := st.chat.flush(w); err != nil {
			return err
		}
	}
	if st.resp != nil {
		return st.resp.flushAll(w)
	}
	return nil
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
		if string(data) == "[DONE]" && st.chat != nil { // end of an OpenAI chat stream
			if err := st.chat.flush(w); err != nil {
				return err
			}
		}
		return writeRaw(w, lines)
	}
	if _, ok := msg["choices"].([]any); ok {
		if st.chat == nil {
			st.chat = &chatState{res: st.res, streams: map[chatKey]*unmask.Stream{}, callIDs: map[chatKey]string{}}
		}
		return st.chat.chunk(w, lines, name, msg)
	}
	if t, _ := msg["type"].(string); strings.HasPrefix(t, "response.") {
		if st.resp == nil {
			st.resp = &respState{res: st.res, streams: map[respKey]*unmask.Stream{}, closed: map[respKey]bool{}}
		}
		return st.resp.event(w, lines, name, t, msg)
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
