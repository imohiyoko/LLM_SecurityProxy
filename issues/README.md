# Security review findings

Static security review of this repository at commit
`aa8269efc12e12e841817b112929c9cbb90b6f1d`, focused on the core invariant that
no unmasked secret/PII reaches the upstream LLM and that placeholder mappings
do not cross context boundaries.

Each file is a self-contained, independently fixable finding with code
references (permalinks pinned to the reviewed commit), reproduction against the
compiled `Default()` detector where applicable, impact, and a suggested fix.

| # | Severity | Finding |
|---|----------|---------|
| H1 | HIGH | [Placeholder mapping is a process-global, unexpiring bearer token](h1-placeholder-bearer-token.md) |
| H2/H3 | HIGH | [generic `assignment` rule misses alpha-only secrets and SNAKE_CASE keys](h2h3-generic-assignment-gaps.md) |
| M1 | MEDIUM | [Fake-placeholder wrapping bypasses masking](m1-fake-placeholder-bypass.md) |
| M2 | MEDIUM | [Request headers and query string are forwarded unmasked](m2-headers-query-unmasked.md) |
| M3 | MEDIUM | [Credit-card regex digit range vs luhn validator](m3-credit-card-digit-range.md) |
