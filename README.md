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

> Status: early MVP. Anthropic Messages API (streaming and non-streaming) is
> supported. OpenAI-compatible APIs are planned.

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

## Rules

Detection rules are grouped into **rulesets**, YAML files with an ID. A rule is
addressed as `<ruleset id>:<rule id>`, e.g. `builtin/pii:email`.

| Ruleset | Default | Contents |
|---|---|---|
| `builtin/credentials` | on | private keys (PEM, PGP), AWS keys, GitHub / GitLab / Slack (incl. app-level) / Anthropic / OpenAI / Google / Stripe / npm tokens, Slack webhooks, JWTs, passwords in URLs (`scheme://user:pass@host`), `Authorization` header credentials |
| `builtin/pii` | on | e-mail addresses, card numbers (Luhn-checked) |
| `builtin/generic` | on | `password=` / `api_key:` / `HF_TOKEN=` style assignments (also `:=`, `=>`, XML elements, PHP `define()`) |
| `builtin/network` | off | IPv4 addresses |

Add your own rulesets as `*.yaml` files in `rules.d/` next to your config (see
[`examples/rules.d/example.yaml`](examples/rules.d/example.yaml)): literal
values (host names, customer names, ...) or regular expressions, each with its
own allow patterns. A file with the same ID as a built-in ruleset replaces it.
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
context that first revealed it.

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
