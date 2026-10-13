# Design

## Goal

Let coding agents use a hosted LLM without sending secrets or confidential
identifiers in prompts or in the material the agent reads (files, command
output, tool results), while keeping the agent useful: when the model refers to
a masked value, the agent must still receive and write the real value locally.

## Topology

```
agent ──HTTP──► llmsp on loopback ──HTTPS via upstream proxy──► LLM API
```

llmsp is a reverse proxy selected by the agent's base URL setting
(`ANTHROPIC_BASE_URL`, an OpenAI `base_url`, ...). It is not a TLS-intercepting
forward proxy, so no CA certificate has to be installed for the agent. Outbound
traffic honours `HTTPS_PROXY` or an explicit `upstream.proxy`, with an optional
extra CA bundle for TLS-inspecting proxies.

## Request path

1. Read the body (bounded). Reject compressed or non-JSON bodies (fail closed).
2. Walk the JSON and mask every content string.
   - Protocol fields (`type`, `id`, `tool_use_id`, `signature`, base64 `data`,
     ...) are skipped, but only at the protocol level. Everything inside tool
     arguments (`input` of a `tool_use` block, `arguments`) is content,
     whatever its keys are called. The top-level `input` of the OpenAI
     Responses API is the conversation, not a tool argument: its protocol
     fields and reasoning items are still skipped.
     Object keys inside tool arguments are masked too: streamed tool input is
     restored as raw JSON, keys included, and comes back as history on the
     next turn. A masked key that would collide with another key of the same
     object gets a ` (2)`, ` (3)`, ... suffix, so no member is dropped and the
     same history is masked the same way every turn.
   - Plain-text document sources (`media_type: text/*`) are content.
   - `thinking` / `redacted_thinking` / `reasoning` blocks are passed through
     byte for byte: they are signed and editing them makes the API reject the
     request.
3. Mask header values and query keys and values the same way. Only the
   headers in `upstream.auth_headers` (default `Authorization`, `X-Api-Key`)
   are forwarded unmasked; they carry the upstream credential. An unchanged
   query is forwarded byte for byte; a malformed one is rejected. The URL path
   is forwarded as is.
4. Add a notice explaining placeholders: appended to the system prompt
   (Anthropic), to a leading system or developer message or as a new first
   system message (Chat Completions), or as a first developer message in
   `input` (Responses; `instructions` is left alone, since some backends
   accept only the client's own there; none when `previous_response_id` or
   `conversation` is set, as the server keeps the first turn's).
5. Forward.

### Rulesets

Rules are data, not code. A ruleset is a YAML file:

```yaml
id: org/internal              # lowercase, digits, . _ - and / separators
description: ...
default: true                 # on unless config says otherwise
rules:
  - id: hosts                 # unique within the ruleset
    kind: HOST                # label in the placeholder
    values: [...]             # literal values, or values_file (relative path)
    case_insensitive: true
  - id: code
    kind: PROJECT
    pattern: '...'            # RE2; exactly one of pattern / values / keys
    group: 1                  # mask one capture group only
    # groups: [1, 2]          # or: the first of these groups that matched
    allow: ['...']            # values matching these are not masked
    validators: [luhn]        # named checks a regexp cannot express
    enabled: true
  - id: customer
    kind: CUSTOMER
    keys: [customer_name]     # field names: mask the whole value of the field
```

- Built-in rulesets are embedded files in the same format
  (`internal/rules/builtin`), so every default is visible and overridable.
- User rulesets come from `<config dir>/rules.d` and `rulesets.dirs`. A user
  ruleset with a built-in ID replaces the built-in one entirely; two user files
  with the same ID are an error.
- Effective state: ruleset `default`, then `rulesets.enable`, then
  `rulesets.disable`, each taking ruleset IDs or rule IDs. A rule-level entry
  overrides its ruleset's state. Unknown IDs and unknown YAML fields are errors,
  so a typo cannot silently turn a rule off.
- `.env` files are deliberately not used: they cannot express structure,
  regular expressions are awkward to escape in them, and they live in project
  directories that agents read and that tend to get committed.

### Field rules

A rule with `keys:` masks the whole value assigned to a field with one of
those names. It is for data that has no recognisable format, such as
person names (`builtin/pii:name`), where only the field name says what the
value is.

- Names are compared after normalisation: split on any character that is not
  a letter or digit and on camelCase boundaries, lower-cased, and joined
  without the breaks. `userName`, `user_name`, `user-name`, `USER_NAME`,
  `user.name` and `username` all compare equal. The whole name must match a
  key; a longer name (`billing_user_name`, `userNameKana`) does not. A dotted
  path also matches on its last segment (`self.user_name`,
  `profile.displayName`).
- In text, a field is a name of letters, digits, `_ . -` in any script,
  optionally quoted (`"name"`, `'name'`, `\"name\"`), a Ruby symbol, a
  command-line flag (`--name`) or a subscript (`['name']`), followed by `:`,
  `=`, `:=`, `=>` or a full-width colon. A quote before the name that does
  not close it belongs to an enclosing string (`-e "FULL_NAME=..."`). A label
  of two to four words at the start of a line (`Full Name:`) and a one-line
  XML element (`<first_name>...</first_name>`) are fields too. This covers
  JSON, YAML, logfmt, env and shell, HTML attributes, forms and most
  languages' assignments and keyword arguments.
- A quoted value runs to its closing quote on the same line, spaces,
  backslash escapes and doubled quotes (`'O''Brien'`) included; a string
  prefix (`u'..'`, `f".."`) is skipped. An unquoted value runs to the end of
  the line, and stops earlier at a tab, a quote (not an apostrophe inside a
  word: `O'Brien`), `=` or one of ``< > | ` `` and an unbalanced `) ] }`; at a
  space, `,`, `;` or `&` followed by another `name=` / `name:`; and at ` #`.
  Running on rather than stopping at a space masks free text that follows a
  name instead of leaking its second word.
- No value is read when the separator is followed by another field
  (`user_name= display_name=...`), a nested structure, or a YAML block,
  anchor, alias or tag. Unquoted values that are code are skipped for every
  field rule: calls and subscripts, templates and variables, expressions,
  type annotations (`user_name: str = ...`). Quoted values are always data.
- In request JSON, a string member of an object inside tool arguments is
  matched by its key directly, without reading text. Header names (without
  an `X-` prefix) and query keys are used the same way for their values.
- `allow` and `validators` apply to the whole value. The builtin allow list
  skips values that are not names: no letters at all, a lone placeholder,
  lower-case placeholder words and system or service accounts (`null`,
  `root`, `postgres`, ...), and references to other fields (`first_name`,
  `request.user.name`, `currentUser`).

### Masking a string

1. Collect spans from: existing placeholders, enabled rules, and every value
   already in the store (exact match, minimum length 6, not inside a longer
   run of ASCII letters and digits). An existing
   placeholder is protected only if the store issued its ID under exactly
   that kind; any other placeholder-shaped text is masked as a whole, since
   its kind segment can hide a token that detectors miss there.
2. Drop allowlisted values, so that an allowed span cannot hide a secret
   inside it.
3. Resolve overlaps: protected first, then earliest, then longest. Field
   values come last: each is masked in the pieces the other spans leave of
   it. A field value can stop inside a secret (at the `=` of a URL password)
   or contain a placeholder; masking it whole would drop the other span and
   leave the secret's tail in plaintext. A field value read from text is
   also split at backslash escapes, so its pieces restore anywhere without
   extra backslashes, and it is stored unescaped as well, so the known-value
   pass finds it in decoded text.
4. Store the spans and substitute placeholders.
5. Record the IDs substituted; they are the request's restore scope.

The known-value pass matters. After a response is unmasked, the agent's history
contains the real value, often without the context (`password=`) that a
detector needs. Exact matching against stored values masks it again.

Values found by field rules go through the same pass with the same policy: at
least 6 bytes, matched anywhere outside a longer word, persisted in the
store like every other value. So a name seen once in a field (`"userName": "Jane Doe"`) is masked in
later free text (`Jane Doe joined the call`), which is the point of field
rules. The trade-offs are accepted deliberately:

- A short name (`Bob`) is masked in its field but not in free text.
- A known value inside a longer run of ASCII letters and digits is a
  different value and is not masked (`Jordan` in `Jordanian`, a card number
  followed by more digits); masking part of it would also leave the rest in
  plaintext. Any other character is a boundary, so a value next to Japanese
  text (`カード番号1234...`, a two-character CJK name before `さん`) or after
  an escape (`\n`, `%3D`) is still masked.
- Masking a common word everywhere is visible to the model as a placeholder.
  Account names that are common words (`root`, `postgres`, `deploy`) are on
  the builtin allow list for this reason.
- Learning a value changes how earlier history is masked on the next turn,
  so the cached prompt prefix changes once. This holds for every learned
  value, not only field-derived ones.

Long strings are memoized because history is resent on every turn. The cache
is invalidated whenever the set of known values changes, so a newly learned
value is never missed. A result is cached only under the version of the known
values it was computed with: when a concurrent request learns a value while a
string is being masked, the result is not cached under the newer version, and
the next turn masks the string again with the value included.

## Placeholders

`__LLMSP_<KIND>_<id>__`, where `id` is 12 hex characters of
`HMAC-SHA256(k_id, value)`.

- Deterministic: the same value always yields the same placeholder. Resent
  history masks identically, so the model sees a consistent conversation and the
  prompt prefix stays byte-identical for prompt caching.
- Opaque: the HMAC key is secret; the ID says nothing about the value.
- Identifier-shaped: valid in most languages, needs no escaping in JSON or
  shell, and models reproduce it reliably.
- The kind helps the model understand context. A value keeps the kind it was
  first stored with, and only that spelling counts as an issued placeholder.
- Not a bearer token: a response restores only the placeholders issued while
  masking its own request (step 4 above). History is resent every turn, so
  every value the model can legitimately refer to is masked again in the
  current request; a placeholder that leaked elsewhere and comes back on its
  own is left as is.

## Response path

- `application/json`: walk and restore placeholders (thinking blocks excluded),
  including object keys inside tool input, as the streaming path does. A
  restored key that would collide with another key is left as a placeholder.
  An OpenAI `arguments` member is JSON source in a string, so values restored
  into it are JSON-string-escaped. On the request side `arguments` is decoded
  and its values masked, then re-encoded only if something was masked: the
  client sends restored arguments back verbatim, and a known value's escaped
  form would not match it. Arguments that are not JSON are masked as text;
  for them, and for JSON source anywhere, the known-value pass also looks for
  each value's JSON-escaped form. Its placeholder stands for the escaped text
  matched, so restoring it gives back exactly what was written, in a string
  literal or a shell command as much as in JSON.
- `text/event-stream`, Anthropic Messages: per content block, run a stream
  unmasker.
  - `text_delta`: restore as is.
  - `input_json_delta`: the text is a fragment of JSON source, so restored
    values are JSON-string-escaped.
  - A tail that could be the start of a placeholder is held back until it is
    complete or ruled out (at most one placeholder length). Held text is
    flushed before `content_block_stop`.
  - `thinking_delta` is not restored: the thinking block comes back verbatim in
    the next request and must still match its signature.
- `text/event-stream`, OpenAI Chat Completions (`choices` in the data): one
  stream unmasker per choice `delta.content`, `delta.refusal`, tool call
  `function.arguments` and legacy `function_call.arguments` (the last two
  JSON-escaped). A choice or tool call without `index` is keyed by its
  position; a new tool call `id` at the same position starts a new stream,
  and the old one's held text goes out under its own id. Held text is added to the chunk that carries the choice's
  `finish_reason`, in key order, or sent in one more chunk before `[DONE]` or
  at the end of the stream.
- `text/event-stream`, OpenAI Responses (`response.*` events): one stream
  unmasker per `*.delta` source (output text, refusal, function and MCP call
  arguments, custom tool input). Before the matching `*.done` event, held text
  goes out as one more delta; the full value in the done event is restored
  too. A done event that lacks an index its deltas had is matched to the only
  stream of its type for the same item that is still open and whose indexes
  agree where both have one. Anything still held goes out before `response.completed`,
  `.incomplete` or `.failed`, or at the end of the stream. Items, content parts
  and the final response are restored whole. `sequence_number` is renumbered,
  since held deltas are dropped and flush deltas added.
  - Reasoning is left masked: reasoning items and every `*reasoning*` event.
    The client sends reasoning items back, and the request side does not mask
    them, so a restored summary would go upstream in plaintext.
- An event with nothing restored is passed through byte for byte. The
  restored count counts each placeholder once, though it appears in deltas,
  the done event, the item and the final response.
- IDs outside the request's scope, and unknown IDs, are left untouched.

## Storage

`<data_dir>/master.key` (32 random bytes, mode 0600) and `<data_dir>/llmsp.db`
(SQLite). HKDF derives separate keys for encryption and for IDs. Each value is
sealed with AES-256-GCM using its ID as associated data. Values are decrypted
into memory at start-up.

## Security notes

- Loopback only by default; responses contain restored secrets.
- Logs record counts per kind, never values.
- The client's API key (`upstream.auth_headers`) is forwarded unchanged; llmsp
  does not store it.

## Not yet

- OS keychain for the master key; retention / expiry of stored values.
- NER-based detection (names, organisations) in free text. Names are only
  found by their field name, and in free text once seen in a field.
- A CLI to list, look up and purge stored values.
