# LLM Security Proxy (llmsp)

A local proxy that masks sensitive values before they leave your machine for an
LLM API, and restores them in the response.

```
coding agent (Claude Code, ...) ──► llmsp (127.0.0.1) ──► [corporate proxy] ──► LLM API
                                    mask request  ◄──────────────────────────  unmask response
```

- Secrets in prompts **and in what the agent reads** (file contents, command
  output, tool results) are replaced with placeholders such as
  `__LLMSP_AWS_ACCESS_KEY_3f9a1c2b5d0e__`.
- Originals are stored locally, encrypted (AES-256-GCM). Only placeholders reach the API.
- The model is told what placeholders are and to copy them verbatim.
- Placeholders in the model's reply — text **and tool call arguments** — are
  restored before the agent sees them, so files and commands get the real values.

> Status: early MVP. Supported APIs, streaming and non-streaming: Anthropic
> Messages, OpenAI Chat Completions and OpenAI Responses (Codex).

## Quick start

```sh
go install github.com/imohiyoko/LLM_SecurityProxy/cmd/llmsp@latest
llmsp                       # listens on 127.0.0.1:8787

# in another shell
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
export NO_PROXY=127.0.0.1,localhost   # if you also set HTTPS_PROXY
claude
```

Outbound traffic uses `HTTPS_PROXY` / `HTTP_PROXY`, or `upstream.proxy` in the
config. See [`config.example.yaml`](config.example.yaml).

`GET /_llmsp/health` is answered by llmsp itself, never forwarded: `200
{"status":"ok"}` when the listener can run its rules and write its database,
`503 {"status":"error","error":"masking"|"store"}` otherwise; the cause is in
the log. Use it from scripts and hooks to tell a working proxy from a port that
is merely open.

### One endpoint per client

`profiles` runs several listeners in one process, each with its own upstream
(base URL, outbound proxy, CA file, credential headers). Point each client at
its own port:

```yaml
upstream:                 # defaults for every profile
  base_url: https://api.anthropic.com
profiles:
  claude:
    listen: 127.0.0.1:8787
  codex:
    listen: 127.0.0.1:8788
    upstream:
      base_url: https://api.openai.com/v1
      auth_headers: [Authorization]
```

To run a single profile, possibly on another port, use
`llmsp serve -profile codex [-listen 127.0.0.1:9000]`; only that profile's
settings are checked. Separate processes on one data directory share the key
and database, and pick up values the others learned within a second; one
process serving every profile shares them at once.

Log lines carry `profile=<name>`. All profiles share one key and database, so a
value gets the same placeholder whichever client sent it; a response still only
restores the placeholders issued for its own request.

Each profile can also mask differently. Its `rulesets.enable` / `disable`
override the top-level selection for the IDs they name, and its `allowlist` is
added to the top-level one:

```yaml
profiles:
  standard:               # the top-level rules
    listen: 127.0.0.1:8787
  strict:
    listen: 127.0.0.1:8788
    rulesets:
      enable: [builtin/network]
  light:
    listen: 127.0.0.1:8789
    rulesets:
      disable: [builtin/pii]
```

A value masked once by any profile is still masked by exact match in every
profile, whatever its rules, so a lighter profile never sends what a stricter
one has already masked. `llmsp profiles` lists the listeners with the number of
rules each applies, and `llmsp rules list -profile NAME` /
`llmsp rules test -profile NAME FILE` show one profile's rules.

### One port, a profile per client

`routes` picks the profile per request on the top-level `listen` address, so
every client can use the same port. The first route whose conditions all hold
wins; a request no route matches uses the top-level settings. Profiles used
only through routes need no `listen`.

```yaml
listen: 127.0.0.1:8787
upstream:
  base_url: https://api.anthropic.com
profiles:
  claude:
    rulesets:
      enable: [builtin/network]
  codex:
    upstream:
      base_url: https://api.openai.com/v1
      auth_headers: [Authorization]
  cline:
    rulesets:
      disable: [builtin/pii:name]
routes:
  - client: claude-code       # Claude Code: ANTHROPIC_BASE_URL=http://127.0.0.1:8787
    profile: claude
  - client: codex             # Codex: base_url = "http://127.0.0.1:8787"
    profile: codex
  - path_prefix: /cline       # Cline: base URL http://127.0.0.1:8787/cline
    profile: cline
  - header: {X-Llmsp-Profile: '^strict$'}
    profile: claude
```

Conditions:

- `client` recognises a client by headers it sends: `claude-code` by
  `X-Claude-Code-Session-Id` (documented in Claude Code's LLM gateway
  protocol), `codex` by an `Originator` header starting with `codex` (set by
  the Codex CLI), `cline` by `X-Title: Cline` (sent to Cline's own API only).
- `header` maps header names to RE2 patterns; an empty pattern only requires
  the header. Clients can add one: Claude Code with `ANTHROPIC_CUSTOM_HEADERS`,
  Codex with `http_headers` in its model provider, Cline's OpenAI Compatible
  provider with custom headers. Headers named `X-Llmsp-*` are never forwarded.
- `path_prefix` works with any client whose base URL can be set; the prefix is
  removed before forwarding.

The upstream base URL already holds the API path, so point Codex at the bare
address (`http://127.0.0.1:8787`, no `/v1`); it then requests `/responses`.
`llmsp profiles` lists the routes in matching order with each profile's rule
count. The health endpoint answers on the routing port, and below a path
prefix for that route's profile.

### Relaxing for a while

Keep strict profiles in force and switch to a looser one only for a set time.
A profile with `relax` may serve the requests routed to the profiles it
`replaces`; how long is set per profile:

```yaml
profiles:
  strict: {}
  loose:
    rulesets:
      disable: [builtin/pii:name]
    relax:
      replaces: [strict, default]   # default: requests no route matched
      default: 1h                   # when -for is not given
      max: 8h                       # longest allowed
routes:
  - client: claude-code
    profile: strict
```

```sh
llmsp relax loose            # for relax.default
llmsp relax -for 2h loose    # up to relax.max
llmsp relax                  # what is in effect, and for how long
llmsp relax -off             # end it now
```

The state is `relax.json` in the data directory. The running proxy reads it
within a second and checks the expiry on every request, so a relaxation ends on
time even across restarts; an unreadable or over-long one is ignored. Requests
served this way are logged with `relaxed_from` and `relaxed_until`, and the
start and end are logged once. Only the routing listener relaxes; a profile's
own `listen` is not affected.

Requests are masked whatever the API. Placeholders are restored in JSON
replies of any API, and in streamed replies of Anthropic Messages, OpenAI Chat
Completions and OpenAI Responses, including tool call arguments; streams in
other formats pass through unchanged. The placeholder
notice goes into the system prompt (Anthropic), a leading system message
(Chat Completions) or a leading developer message in `input` (Responses).

## Rules

Detection rules are grouped into **rulesets**, YAML files with an ID. A rule is
addressed as `<ruleset id>:<rule id>`, e.g. `builtin/pii:email`.

| Ruleset | Default | Contents |
|---|---|---|
| `builtin/credentials` | on | private keys (PEM, PGP), AWS keys, GitHub / GitLab / Slack (incl. app-level) / Anthropic / OpenAI / Google / Stripe / npm tokens, Slack webhooks, JWTs, passwords in URLs (`scheme://user:pass@host`), `Authorization` header credentials |
| `builtin/pii` | on | e-mail addresses, card numbers (Luhn-checked), person names by field name (`userName`, `display_name`, `FULL_NAME`, ...) |
| `builtin/generic` | on | `password=` / `api_key:` / `HF_TOKEN=` style assignments (also `:=`, `=>`, XML elements, PHP `define()`) |
| `builtin/network` | off | IPv4 addresses |

Add your own rulesets as `*.yaml` files in `rules.d/` next to your config (see
[`examples/rules.d/example.yaml`](examples/rules.d/example.yaml)): literal
values (host names, customer names, ...) or regular expressions, each with its
own allow patterns, or field names (`keys:`) whose values are masked whole
however the name is spelled. A file with the same ID as a built-in ruleset replaces it.
Turn rulesets or single rules on and off in `config.yaml`:

```yaml
rulesets:
  enable: [builtin/network]
  disable: [builtin/pii:email]
```

```sh
llmsp rules list              # every rule, on/off, and where it came from
llmsp rules test notes.txt    # what would be masked (nothing is stored or sent)
```

A value that was masked once is masked everywhere afterwards, even without the
context that first revealed it, unless it is part of a longer run of ASCII letters
and digits (`<card number>2112` is a different value and is left as it is).

### Sharing rulesets with a team

Rulesets are plain files, so a team can keep them in a private repository and
point every member's config at a checkout:

```
team-llmsp-rules/          # private repository, cloned by each member
  org-hosts.yaml           # id: org/hosts
  hosts.txt                # values_file of org/hosts, resolved next to it
  org-fields.yaml          # id: org/fields
```

```yaml
# each member's config.yaml
rulesets:
  dirs: [~/src/team-llmsp-rules]
```

- Only the rules are shared. `config.yaml` is per user (there is no include),
  so each member adds the `dirs` entry and their own `enable` / `disable`.
- Use a namespaced ruleset ID (`org/...`). Two user ruleset files with the
  same ID are an error, across `rules.d` and every directory in `dirs`, so
  personal additions need their own ID (`me/...`).
- A shared ruleset can ship with `default: false` and be turned on per user
  with `rulesets.enable`. A shared file with a built-in ID (`builtin/pii`)
  replaces that built-in ruleset for everyone who uses it.
- Rules are read at start-up. After pulling changes, restart llmsp, then check
  with `llmsp rules list` (state and source of every rule) and
  `llmsp rules test FILE`.
- Never share `master.key` or `llmsp.db`. They hold the real values masked on
  one machine and are specific to it.

## How it works

See [docs/design.md](docs/design.md). In short:

- Placeholder IDs are an HMAC of the value, so the same value always gets the
  same placeholder. History is resent every turn; deterministic masking keeps it
  consistent and keeps prompt caching effective.
- Streaming responses are unmasked incrementally. A tail that might be the start
  of a placeholder is held back until it is complete.
- Requests that cannot be inspected (non-JSON, compressed) are rejected, not forwarded.
- Thinking blocks are passed through unmodified (they are signed).

## Limitations

- The model cannot compute with a masked value (e.g. derive a subnet from an IP).
- If the model alters a placeholder (re-cases, splits, encodes it), it cannot be restored.
- Only traffic sent through the proxy is protected. Web fetches, MCP servers and
  other tools that talk to the network directly are out of scope.
- Detection is pattern-based. It reduces exposure; it does not guarantee it.
- Anyone who can reach the listener can read restored values, so it only listens on loopback by default.
- Placeholders are restored in tool call arguments too. A prompt injection that
  gets the model to put a placeholder from the request into a tool call that
  sends data out (a fetch, a shell command) delivers the real value there.
- Routing picks a profile from headers and path prefixes the client sends. It is
  a convenience, not an enforcement boundary: any process that can reach the
  listener can choose a looser profile.

## Contributing

```sh
git config core.hooksPath .githooks   # gitleaks + private denylist on commit
go test ./...
```

This is a public repository. Do not commit environment-specific values:
keep them in your own config and ruleset files. Test fixtures build fake credentials at run
time (`internal/testsecret`) so the repository contains no secret-looking literals.

The commit hooks check staged changes and commit messages against a private
denylist at `~/.config/llmsp/denylist.txt` (one term per line), which is never
committed.
