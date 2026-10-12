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
4. Append a notice to the system prompt explaining placeholders.
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
  a letter or digit and on camelCase boundaries, lower-cased. `userName`,
  `user_name`, `user-name`, `USER_NAME` and `user.name` are all `user name`.
  The whole name must match a key; a longer name (`billing_user_name`,
  `userNameKana`) does not. A dotted path also matches on its last segment
  (`self.user_name`, `profile.displayName`).
- In text, a field is a name, optionally quoted (`"name"`, `'name'`,
  `\"name\"`) or a Ruby symbol, followed by `:`, `=`, `:=` or `=>`. This
  covers JSON, YAML, logfmt, env and shell, HTML attributes and most
  languages' assignments and keyword arguments. A quoted value runs to its
  closing quote on the same line, spaces and escapes included. An unquoted
  value runs to the end of the line, and stops earlier at a tab, a quote,
  `=` or one of ``) ] } < > | ` ``; at a space, `,`, `;` or `&` followed by
  another `name=` / `name:`; and at ` #`. Running on rather than stopping at a
  space masks free text that follows a name instead of leaking its second
  word. Values that start a nested structure or a YAML block, anchor, alias
  or tag are skipped.
- In request JSON, a string member of an object inside tool arguments is
  matched by its key directly, without reading text. Header names and query
  keys are used the same way for their values.
- The value is masked whole; `allow` and `validators` apply to it as usual.
  The builtin allow list skips values that are not names: no letters at all,
  `null` / `admin` / `root` style words, references such as `first_name` or
  `request.user.name`, type annotations, calls and templates.

### Masking a string

1. Collect spans from: existing placeholders, enabled rules, and every value
   already in the store (exact match, minimum length 6). An existing
   placeholder is protected only if the store issued its ID under exactly
   that kind; any other placeholder-shaped text is masked as a whole, since
   its kind segment can hide a token that detectors miss there.
2. Resolve overlaps: protected first, then earliest, then longest.
3. Skip allowlisted values; store the rest and substitute placeholders.
4. Record the IDs substituted; they are the request's restore scope.

The known-value pass matters. After a response is unmasked, the agent's history
contains the real value, often without the context (`password=`) that a
detector needs. Exact matching against stored values masks it again.

Values found by field rules go through the same pass with the same policy: at
least 6 bytes, matched anywhere, persisted in the store like every other
value. So a name seen once in a field (`"userName": "Jane Doe"`) is masked in
later free text (`Jane Doe joined the call`), which is the point of field
rules. The trade-offs are accepted deliberately:

- A short name (`Bob`) is masked in its field but not in free text.
- A name of 6 bytes or more is masked inside longer words too (`Jordan` in
  `Jordanian`). A two-character CJK name is already 6 bytes.
- Masking a common word everywhere is visible to the model as a placeholder.

Long strings are memoized because history is resent on every turn. The cache
is invalidated whenever the set of known values changes, so a newly learned
value is never missed.

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
- `text/event-stream`: parse events; per content block, run a stream unmasker.
  - `text_delta`: restore as is.
  - `input_json_delta`: the text is a fragment of JSON source, so restored
    values are JSON-string-escaped.
  - A tail that could be the start of a placeholder is held back until it is
    complete or ruled out (at most one placeholder length). Held text is
    flushed before `content_block_stop`.
  - `thinking_delta` is not restored: the thinking block comes back verbatim in
    the next request and must still match its signature.
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

- OpenAI Chat Completions / Responses (Codex, Cline). Function call
  `arguments` are JSON strings and need JSON-escaped restoration.
- OS keychain for the master key; retention / expiry of stored values.
- NER-based detection (names, organisations) in free text. Names are only
  found by their field name, and in free text once seen in a field.
- A CLI to list, look up and purge stored values.
