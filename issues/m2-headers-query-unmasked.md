# [security] Request headers and query string are forwarded upstream without masking

## Summary
Masking runs only over the JSON request body. Request headers (minus hop-by-hop) and the URL query string are forwarded to the upstream verbatim, so a secret carried there is not masked even when the same value in the body would be.

## Affected code
- Query forwarded as-is: [proxy.go#L63-L65](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/proxy/proxy.go#L63-L65)
- Headers cloned and forwarded (only hop-by-hop removed): [proxy.go#L72-L75](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/proxy/proxy.go#L72-L75)
- maskRequest walks body JSON strings only: [proxy.go#L126-L152](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/proxy/proxy.go#L126-L152)

## Impact
Forwarding the upstream auth header (`x-api-key`) is intentional, but any other secret-bearing header (e.g. a second `Authorization: Bearer …`, a custom `X-*-Token`) or a `?key=<secret>` style query reaches the provider in cleartext. The protection differs purely by transport location.

## Suggested fix
- Run the same detect/mask pipeline over forwarded header values (excluding the intended auth header) and over decoded query values.
- Or document explicitly that masking covers the JSON body only, so the stated invariant matches the implementation.
