# [security] generic `assignment` rule misses alpha-only secrets (<=23 chars) and SNAKE_CASE key names (SECRET_KEY=, PASSWORD_HASH=)

The only context-based detector for format-less secrets (`builtin/generic:assignment`) has two gaps that let real credentials through unmasked. Both reproduced against the compiled `Default()` detector.

### Gap 1 — allow list drops alpha-only values up to 23 chars
`allow: '^[A-Za-z_]{1,23}$'` is intended to drop identifiers like `tokenValue`, but it also drops real passphrases that are letters-only and <=23 chars.
[generic.yaml#L12-L17](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/rules/builtin/generic.yaml#L12-L17)
```
password=MyPlainSecretValue        -> 0 matches (NOT masked; 18 letters)
password=abcdefghijklmnopqrstuvw   -> 0 matches (NOT masked; 23 letters)
password=abcdefghijklmnopqrstuvwx  -> masked (24 chars)
password=MyPlainSecret1Value       -> masked (contains a digit)
```

### Gap 2 — `\b` after the keyword fails on SNAKE_CASE names
(Here `<value>` is any secret-shaped value containing at least one digit, so Gap 1's alpha-only allow does not apply.)

The keyword alternation is followed by `\b`. In `SECRET_KEY`, `secret` is followed by `_` (both word chars), so no boundary exists and the rule never fires.
[generic.yaml#L10](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/rules/builtin/generic.yaml#L10)
```
SECRET_KEY=<value>     -> 0 matches
SECRET_TOKEN=<value>   -> 0 matches
PASSWORD_HASH=<value>  -> 0 matches
API_KEY=<value>        -> masked   (pattern itself contains _key)
SECRET=<value>         -> masked
```

## Impact
`.env` / framework config such as `SECRET_KEY=...`, `PASSWORD_HASH=...`, or an alpha-only passphrase is forwarded to the upstream LLM in cleartext when the value has no other recognizable format.

## Suggested fix
- Gap 1: drop or tighten `^[A-Za-z_]{1,23}$` (limit to very short identifiers, or distinguish by entropy / char-class rather than a fixed length).
- Gap 2: remove the trailing `\b` and consume the identifier remainder before `[:=]`, e.g. `(?:secret|password|...)[A-Za-z0-9_]*\s*[:=]`, or enumerate `*_key` / `*_token` explicitly.
