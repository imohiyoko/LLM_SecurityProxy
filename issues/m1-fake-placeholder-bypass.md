# [security] A value wrapped as a fake placeholder (__LLMSP_<VALUE>_<12hex>__) bypasses masking

## Summary
`mask()` treats anything matching the placeholder pattern as an existing placeholder to keep and forward verbatim. The placeholder KIND charset is `[A-Z0-9_]{1,32}`, which overlaps with uppercase-alphanumeric secrets (e.g. an AWS access key id). Wrapping such a secret as a fake placeholder makes the keep-span cover and discard the real detection span, so the secret is forwarded unmasked.

## Affected code
- Existing placeholders become keep spans: [mask.go#L107-L109](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/mask/mask.go#L107-L109)
- keep sorts first, so it wins overlap resolution: [mask.go#L133-L143](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/mask/mask.go#L133-L143)
- greedy selection discards detection spans overlapping a keep span: [mask.go#L144-L156](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/mask/mask.go#L144-L156)
- keep spans are emitted verbatim: [mask.go#L162-L165](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/mask/mask.go#L162-L165)
- placeholder pattern / KIND charset: [placeholder.go#L27](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/placeholder/placeholder.go#L27)

## Reproduction
Against the compiled `Default()` detector + masker, using the AWS documentation EXAMPLE key as the value:
```
bare:     "key AKIA…EXAMPLE here"
          -> "key __LLMSP_AWS_ACCESS_KEY_<id>__ here"        (masked)
wrapped:  "key __LLMSP_AKIA…EXAMPLE_0123456789ab__ here"
          -> forwarded verbatim; the real key is still present (masking bypassed)
```

## Impact
Under the project's threat model (the agent also reads files / tool results), attacker-controlled tool/MCP output or a file can shape a user's uppercase-alnum secret into `__LLMSP_<SECRET>_<12hex>__`; the proxy then forwards it unmasked to the provider.

## Suggested fix
- Treat a placeholder as keep only when its ID actually exists in the store (match the pattern AND resolve the ID); otherwise fall back to normal detection.
- Or, when a keep span overlaps a detection span, let detection win.
- Or narrow the KIND format so it cannot collide with secret tokens.
