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
     arguments (`input`, `arguments`) is content, whatever its keys are called.
   - Plain-text document sources (`media_type: text/*`) are content.
   - `thinking` / `redacted_thinking` blocks are passed through byte for byte:
     they are signed and editing them makes the API reject the request.
3. Append a notice to the system prompt explaining placeholders.
4. Forward.

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
    pattern: '...'            # RE2; exactly one of pattern / values
    group: 1                  # mask one capture group only
    allow: ['...']            # values matching these are not masked
    validators: [luhn]        # named checks a regexp cannot express
    enabled: true
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

### Masking a string

1. Collect spans from: existing placeholders (protected), enabled rules, and
   every value already in the store (exact match, minimum length 6).
2. Resolve overlaps: protected first, then earliest, then longest.
3. Skip allowlisted values; store the rest and substitute placeholders.

The known-value pass matters. After a response is unmasked, the agent's history
contains the real value, often without the context (`password=`) that a
detector needs. Exact matching against stored values masks it again.

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
- The kind is cosmetic (it helps the model understand context); lookup uses the
  ID only. A value keeps the kind it was first stored with.

## Response path

- `application/json`: walk and restore placeholders (thinking blocks excluded).
- `text/event-stream`: parse events; per content block, run a stream unmasker.
  - `text_delta`: restore as is.
  - `input_json_delta`: the text is a fragment of JSON source, so restored
    values are JSON-string-escaped.
  - A tail that could be the start of a placeholder is held back until it is
    complete or ruled out (at most one placeholder length). Held text is
    flushed before `content_block_stop`.
  - `thinking_delta` is not restored: the thinking block comes back verbatim in
    the next request and must still match its signature.
- Unknown IDs are left untouched.

## Storage

`<data_dir>/master.key` (32 random bytes, mode 0600) and `<data_dir>/llmsp.db`
(SQLite). HKDF derives separate keys for encryption and for IDs. Each value is
sealed with AES-256-GCM using its ID as associated data. Values are decrypted
into memory at start-up.

## Security notes

- Loopback only by default; responses contain restored secrets.
- Logs record counts per kind, never values.
- The client's API key is forwarded unchanged; llmsp does not store it.

## Not yet

- OpenAI Chat Completions / Responses (Codex, Cline). Function call
  `arguments` are JSON strings and need JSON-escaped restoration.
- OS keychain for the master key; retention / expiry of stored values.
- NER-based detection (names, organisations).
- A CLI to list, look up and purge stored values.
