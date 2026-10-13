package proxy

import (
	"cmp"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/unmask"
)

// chatState restores an OpenAI Chat Completions stream.
type chatState struct {
	res     unmask.Resolver
	streams map[chatKey]*unmask.Stream
	// last is the latest chunk: the template for a chunk that flushes what
	// is still held when the stream ends.
	last map[string]any
	// callIDs: the tool call id each arguments stream belongs to. Calls
	// without an index all take position 0 when sent one per chunk, so a
	// new id at the same key starts a new stream.
	callIDs map[chatKey]string
	retired int // restored by streams replaced for a new call
}

// chatKey identifies one streamed value. tool is -1 outside tool_calls.
type chatKey struct {
	choice, tool int
	field        string // content, refusal, arguments, function_call
}

func compareChatKeys(a, b chatKey) int {
	return cmp.Or(cmp.Compare(a.choice, b.choice), cmp.Compare(a.tool, b.tool), strings.Compare(a.field, b.field))
}

// chunk restores a chat.completion.chunk: choices[].delta content, refusal,
// tool_calls[].function.arguments and the legacy function_call.arguments.
// When a choice finishes, what its streams still hold is added to the same
// chunk, before the client reads finish_reason. A choice or tool call without
// an index is keyed by its position.
func (c *chatState) chunk(w io.Writer, lines [][]byte, name string, msg map[string]any) error {
	c.last = msg
	changed := false
	write := func(k chatKey, esc unmask.Escaper, in string) string {
		s := c.streams[k]
		if s == nil {
			s = unmask.NewStream(c.res, esc)
			c.streams[k] = s
		}
		out := s.Write(in)
		changed = changed || out != in
		return out
	}
	choices, _ := msg["choices"].([]any)
	for pos, ch := range choices {
		choice, _ := ch.(map[string]any)
		if choice == nil {
			continue
		}
		ci, ok := index(choice)
		if !ok {
			ci = pos
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			delta = map[string]any{}
		}
		for _, f := range []string{"content", "refusal"} {
			if text, ok := delta[f].(string); ok {
				delta[f] = write(chatKey{ci, -1, f}, unmask.Identity, text)
			}
		}
		calls, _ := delta["tool_calls"].([]any)
		var outCalls []any
		for tpos, tc := range calls {
			call, _ := tc.(map[string]any)
			fn, _ := call["function"].(map[string]any)
			if fn == nil {
				outCalls = append(outCalls, tc)
				continue
			}
			ti, ok := index(call)
			if !ok {
				ti = tpos
			}
			k := chatKey{ci, ti, "arguments"}
			if id, _ := call["id"].(string); id != "" {
				// What the previous call at this key still holds is its
				// own: sent under its id, before the new call.
				if prev, seen := c.callIDs[k]; seen && prev != id {
					if old := c.streams[k]; old != nil {
						if rest := old.Flush(); rest != "" {
							outCalls = append(outCalls, map[string]any{"id": prev, "function": map[string]any{"arguments": rest}})
							changed = true
						}
						c.retired += old.Count
						delete(c.streams, k)
					}
				}
				c.callIDs[k] = id
			}
			if args, ok := fn["arguments"].(string); ok {
				fn["arguments"] = write(k, unmask.JSONString, args)
			}
			outCalls = append(outCalls, call)
		}
		if len(outCalls) != len(calls) {
			delta["tool_calls"] = outCalls
		}
		if fc, _ := delta["function_call"].(map[string]any); fc != nil {
			if args, ok := fc["arguments"].(string); ok {
				fc["arguments"] = write(chatKey{ci, -1, "function_call"}, unmask.JSONString, args)
			}
		}
		if choice["finish_reason"] != nil && c.flushChoice(ci, delta) {
			changed = true
			choice["delta"] = delta
		}
	}
	if !changed {
		return writeRaw(w, lines)
	}
	return writeJSON(w, name, msg)
}

// flushChoice adds what choice ci still holds to delta, in key order, and
// reports whether anything was added.
func (c *chatState) flushChoice(ci int, delta map[string]any) bool {
	added := false
	for _, k := range slices.SortedFunc(maps.Keys(c.streams), compareChatKeys) {
		if k.choice != ci {
			continue
		}
		rest := c.streams[k].Flush()
		if rest == "" {
			continue
		}
		added = true
		switch k.field {
		case "content", "refusal":
			text, _ := delta[k.field].(string)
			delta[k.field] = text + rest
		case "arguments":
			calls, _ := delta["tool_calls"].([]any)
			delta["tool_calls"] = append(calls, map[string]any{
				"index":    k.tool,
				"function": map[string]any{"arguments": rest},
			})
		case "function_call":
			fc, _ := delta["function_call"].(map[string]any)
			if fc == nil {
				fc = map[string]any{}
				delta["function_call"] = fc
			}
			args, _ := fc["arguments"].(string)
			fc["arguments"] = args + rest
		}
	}
	return added
}

// flush emits, in one more chunk, what choices that never finished still
// hold: before [DONE], or at the end of a stream without one.
func (c *chatState) flush(w io.Writer) error {
	var choices []any
	for _, ci := range slices.Sorted(maps.Keys(choiceSet(c.streams))) {
		delta := map[string]any{}
		if c.flushChoice(ci, delta) {
			choices = append(choices, map[string]any{"index": ci, "delta": delta})
		}
	}
	if len(choices) == 0 {
		return nil
	}
	chunk := map[string]any{}
	for _, k := range []string{"id", "object", "created", "model"} {
		if v, ok := c.last[k]; ok {
			chunk[k] = v
		}
	}
	chunk["choices"] = choices
	return writeJSON(w, "", chunk)
}

func choiceSet(streams map[chatKey]*unmask.Stream) map[int]bool {
	set := map[int]bool{}
	for k := range streams {
		set[k.choice] = true
	}
	return set
}

func (c *chatState) count() int {
	n := c.retired
	for _, s := range c.streams {
		n += s.Count
	}
	return n
}

// respState restores an OpenAI Responses API stream.
type respState struct {
	res     unmask.Resolver
	streams map[respKey]*unmask.Stream
	order   []respKey        // streams in creation order, for flushing at the end
	closed  map[respKey]bool // streams whose done event came
	named   bool             // events carry an event: line

	// sequence_number is renumbered: a held delta is dropped and a flush
	// delta is added, so the upstream numbers would have gaps and repeats.
	seqSet bool
	seq    float64

	doneN  int // restored in done events that had no stream
	wholeN int // most restored in one whole item, part or response
}

// respKey identifies the value a delta event belongs to. Missing indexes
// are -1.
type respKey struct {
	typ, item       string
	output, content int
}

func newRespKey(typ string, msg map[string]any) respKey {
	k := respKey{typ: typ, output: -1, content: -1}
	k.item, _ = msg["item_id"].(string)
	if f, ok := msg["output_index"].(float64); ok {
		k.output = int(f)
	}
	if f, ok := msg["content_index"].(float64); ok {
		k.content = int(f)
	}
	return k
}

// respDelta describes a delta event type and its done event.
type respDelta struct {
	done  string         // the matching done event type
	field string         // where the done event carries the full value
	esc   unmask.Escaper // how a restored value is written into the value
}

var respDeltas = map[string]respDelta{
	"response.output_text.delta":             {"response.output_text.done", "text", unmask.Identity},
	"response.refusal.delta":                 {"response.refusal.done", "refusal", unmask.Identity},
	"response.function_call_arguments.delta": {"response.function_call_arguments.done", "arguments", unmask.JSONString},
	"response.mcp_call_arguments.delta":      {"response.mcp_call_arguments.done", "arguments", unmask.JSONString},
	"response.custom_tool_call_input.delta":  {"response.custom_tool_call_input.done", "input", unmask.Identity},
}

// respDone maps a done event type to its delta event type.
var respDone = func() map[string]string {
	m := map[string]string{}
	for typ, d := range respDeltas {
		m[d.done] = typ
	}
	return m
}()

// event restores one Responses API event.
//
// Deltas go through a stream that holds back a partial placeholder; the done
// event first gets what is still held as one more delta, then its full value
// restored. Items, content parts and the final response are restored whole.
// Reasoning (items and every reasoning_* event) is left as it is: the client
// sends reasoning items back, and the request side does not mask them.
func (r *respState) event(w io.Writer, lines [][]byte, name, typ string, msg map[string]any) error {
	r.named = r.named || name != ""
	// Numbering starts from the first upstream event, even one held back.
	if n, ok := msg["sequence_number"].(float64); ok && !r.seqSet {
		r.seqSet, r.seq = true, n
	}
	changed := false
	d, isDelta := respDeltas[typ]
	dtyp, isDone := respDone[typ]

	switch {
	case strings.Contains(typ, "reasoning"):

	case isDelta:
		text, _ := msg["delta"].(string)
		k := newRespKey(typ, msg)
		s := r.streams[k]
		if s == nil {
			s = unmask.NewStream(r.res, d.esc)
			r.streams[k] = s
			r.order = append(r.order, k)
		}
		out := s.Write(text)
		if out == "" && text != "" {
			return nil // held back; emitted with a later delta
		}
		msg["delta"] = out
		changed = out != text

	case isDone:
		d := respDeltas[dtyp]
		k, s := r.doneStream(dtyp, msg)
		if s != nil {
			r.closed[k] = true
			if err := r.flushStream(w, k, s); err != nil {
				return err
			}
		}
		if v, ok := msg[d.field].(string); ok {
			out, n := unmask.Replace(v, r.res, d.esc)
			msg[d.field] = out
			changed = out != v
			if s == nil {
				r.doneN += n
			}
		}

	default:
		switch typ {
		case "response.completed", "response.incomplete", "response.failed":
			// The last chance for text held by a delta whose done event
			// never came.
			if err := r.flushAll(w); err != nil {
				return err
			}
		}
		for _, f := range []string{"item", "part", "response"} {
			if v, ok := msg[f]; ok {
				nv, n := restoreStrings(v, r.res)
				msg[f] = nv
				r.wholeN = max(r.wholeN, n)
				changed = changed || n > 0
			}
		}
	}

	if r.renumber(msg) {
		changed = true
	}
	if !changed {
		return writeRaw(w, lines)
	}
	return writeJSON(w, name, msg)
}

// doneStream finds the stream a done event closes: by its full key or, if a
// backend sent an index on only one of the delta and done events, the only
// open stream of that type for the same item whose indexes agree where both
// have one.
func (r *respState) doneStream(dtyp string, msg map[string]any) (respKey, *unmask.Stream) {
	k := newRespKey(dtyp, msg)
	if s := r.streams[k]; s != nil || k.item == "" {
		return k, s
	}
	var found respKey
	n := 0
	agree := func(a, b int) bool { return a == b || a < 0 || b < 0 }
	for _, o := range r.order {
		if o.typ == dtyp && o.item == k.item && !r.closed[o] && agree(o.output, k.output) && agree(o.content, k.content) {
			found = o
			n++
		}
	}
	if n != 1 {
		return k, nil
	}
	return found, r.streams[found]
}

// renumber sets msg's sequence_number to the next one this stream emits and
// reports whether it changed.
func (r *respState) renumber(msg map[string]any) bool {
	n, ok := msg["sequence_number"].(float64)
	if !ok {
		return false
	}
	msg["sequence_number"] = r.seq
	r.seq++
	return r.seq-1 != n
}

// flushStream emits what s still holds as one more delta event of k.
func (r *respState) flushStream(w io.Writer, k respKey, s *unmask.Stream) error {
	rest := s.Flush()
	if rest == "" {
		return nil
	}
	ev := map[string]any{"type": k.typ, "delta": rest}
	if k.item != "" {
		ev["item_id"] = k.item
	}
	if k.output >= 0 {
		ev["output_index"] = k.output
	}
	if k.content >= 0 {
		ev["content_index"] = k.content
	}
	if r.seqSet {
		ev["sequence_number"] = r.seq
		r.seq++
	}
	evname := ""
	if r.named {
		evname = k.typ
	}
	return writeJSON(w, evname, ev)
}

// flushAll emits what every stream still holds, in creation order.
func (r *respState) flushAll(w io.Writer) error {
	for _, k := range r.order {
		if err := r.flushStream(w, k, r.streams[k]); err != nil {
			return err
		}
	}
	return nil
}

// count is the number of placeholders restored. The same placeholder shows
// up in deltas, the done event, the item and the final response; it is
// counted once, from the streams, or from the whole objects if there were
// no deltas.
func (r *respState) count() int {
	n := r.doneN
	for _, s := range r.streams {
		n += s.Count
	}
	return max(n, r.wholeN)
}
