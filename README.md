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

## What is detected

Built-in rules: private keys, AWS access keys and secret keys, GitHub / Slack /
Anthropic / OpenAI / Google API tokens, Slack webhooks, JWTs, e-mail addresses,
credit card numbers (Luhn-checked), and `password=` / `api_key:` style
assignments. IPv4 addresses are opt-in (`detectors.enable: [ipv4]`).

Add your own literal terms (host names, customer names, ...) with
`dictionary`, and exempt values with `allowlist`. A value that was masked once
is masked everywhere afterwards, even without the context that first revealed it.

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
keep them in your own config file. Test fixtures build fake credentials at run
time (`internal/testsecret`) so the repository contains no secret-looking literals.

The commit hooks check staged changes and commit messages against a private
denylist at `~/.config/llmsp/denylist.txt` (one term per line), which is never
committed.
