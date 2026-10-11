# [security] Placeholder mapping is process-global, persistent and ID-only, so a placeholder acts as an unexpiring bearer token for the real value

## Summary
The placeholder→value mapping has no request / session / conversation scope. Resolution is by ID alone, the ID is a deterministic HMAC of the value, and the mapping is persisted (SQLite) with no expiry. A placeholder string is therefore effectively an unexpiring bearer token: anyone who can get a placeholder back through the proxy recovers the original value, from any context.

## Affected code
- Single global map; `entry` carries only kind+value: [store.go#L33-L46](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/store/store.go#L33-L46)
- Resolve by ID alone: [store.go#L195-L201](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/store/store.go#L195-L201)
- Deterministic, persisted ID (HMAC-SHA256, first 12 hex), no TTL: [store.go#L153-L158](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/store/store.go#L153-L158), [store.go#L186-L190](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/store/store.go#L186-L190)
- All connections share one store (Masker and Resolver): [main.go#L131](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/cmd/llmsp/main.go#L131), [main.go#L150](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/cmd/llmsp/main.go#L150)
- Existing placeholders in a request are kept and forwarded upstream verbatim: [mask.go#L107-L109](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/mask/mask.go#L107-L109)
- Responses are unmasked against the global resolver: [proxy.go#L197-L201](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/proxy/proxy.go#L197-L201)
- The injected system Notice tells the model to echo placeholders verbatim: [proxy.go#L26-L30](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/proxy/proxy.go#L26-L30)

## Impact
A placeholder that leaks (upstream provider logs / prompt cache, an artifact the agent wrote, or untrusted content the agent later reads) stays valid forever and resolves across conversations and requests. In an agent setting, untrusted content can carry a known placeholder together with an instruction to emit it; the response path then resolves it into an attacker-chosen sink (file write, shell argument, reply body). The only barrier is that the 48-bit HMAC ID is not guessable — but placeholders are designed to be echoed, so observing one is the expected case rather than an obstacle.

## Suggested direction
- Scope the mapping to the issuing request / session / conversation and resolve only within that scope.
- Bind scope into the ID (e.g. mix a session nonce into the HMAC input), or at minimum resolve only placeholders that were actually produced while masking the same request.
- Add expiry (TTL / generation) so a leaked placeholder stops resolving.
