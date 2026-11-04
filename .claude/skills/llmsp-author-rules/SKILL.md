---
name: llmsp-author-rules
description: Interview the user, read their code, logs and reference material, and write llmsp masking rules (rules.d/*.yaml) for them, asking whenever something is unclear and verifying with `llmsp rules test`. Use when the user wants to add, extend or tune masking rules, set up rules for a profile or client (Claude Code, Codex, Cline), or find what in their code or logs should be masked.
---

# Author llmsp masking rules

Build a ruleset for the user's own environment by looking at their code, logs and
documents, asking about anything you cannot decide, and checking the result
against real samples. Never guess about what is sensitive: ask.

## The one hard rule: where real names go

Rules for a real environment contain real host names, customer names and field
names. Those belong **only** in the user's private location: their `rules.d/` next
to `config.yaml`, or a private repository listed in `rulesets.dirs`.

- Never write them into this repository (rules, tests, docs, examples), a commit
  message, a PR body or a comment. Use invented names (`db.internal.example`,
  `customer_code`) when you need an example here.
- Do not quote real values back in summaries that may be pasted elsewhere.
  Refer to a candidate by rule id and count, and show the value only in the
  terminal conversation when the user needs to judge it.
- Before writing a file, state the full path and confirm it is outside any git
  repository meant to be public. If you cannot tell, ask.

## Rule format (what you can produce)

See `examples/rules.d/example.yaml` and the "Rules" section of `README.md`. In short:

| Need | Use |
|---|---|
| A fixed list of values (hosts, project names) | `values:` or `values_file:` (one per line), `case_insensitive` |
| A value with a recognisable shape (`M-` plus 12 digits) | `pattern:` (RE2), `group:` to mask one capture group |
| A whole field whose name tells it is sensitive | `keys: [customer_code, ...]`; any spelling matches (camel, snake, kebab) |
| A check a regexp cannot express | `validators: [luhn]` |
| Known harmless lookalikes | `allow:` patterns on the rule |
| Defined but off by default | `enabled: false`, switched on with `rulesets.enable` |

Ruleset ids are namespaced (`org/...`, `me/...`). Never reuse a `builtin/*` id
unless the user wants to replace that built-in ruleset. Two user files with the
same id are an error.

## Procedure

Work in this order. Keep each question short and offer a default.

### 1. Read the current state (read-only)

- Find the config: macOS `~/Library/Application Support/llmsp/config.yaml`,
  Linux `~/.config/llmsp/config.yaml`. Read `profiles`, `routes`, `rulesets`,
  `allowlist`.
- Run `llmsp profiles` and `llmsp rules list [-profile NAME]` to see what is on,
  and from where. Do not propose a rule that an enabled one already covers.

If `llmsp` or the config is missing, say so and ask; do not invent paths.

### 2. Interview

Ask, one or two questions at a time (use AskUserQuestion when the answers are
a short list):

1. **Which profile or client** the rules are for, or all of them. Rules go in a
   ruleset; which profile uses it is decided by `rulesets.enable` / `disable`
   in that profile.
2. **What must not leave**: kinds of data (internal hosts, customer ids,
   employee ids, internal URLs, tokens of internal systems, personal data) and
   the consequence of a miss. This sets how aggressive to be.
3. **Strictness**, as a preset to start from:
   - strict: mask by field name and by shape; accept some false positives
   - standard: field names and clear shapes; allow patterns for common noise
   - loose: literal values and unmistakable shapes only
   If the user wants a looser profile only for a while, point to `routes` and
   `llmsp relax` instead of weakening the rules.
4. **What to read**: repositories, log files or directories, schemas, docs. Ask
   for paths or links; do not roam the filesystem.
5. **Cost of over-masking**: masked values reach the model as placeholders, so
   identifiers the model must reason about (table names, public hosts) may be
   better left alone. Ask which ones.

### 3. Collect candidates

Read only what the user pointed at. Look for:

- Field and variable names that carry identifiers or personal data (in code, DB
  schemas, API specs, log formats); group them by spelling variant.
- Values with a fixed shape (id prefixes, fixed-width numbers, internal URL
  forms), found as a pattern across many occurrences.
- Internal host and domain names, repository and service names.
- Log line structure: which fields vary, which are constant, where free text
  (user input) appears.
- Reference material the user gave (docs, wiki pages): naming rules, id
  formats, data classification. Quote the source in your notes to the user so
  they can check it.

For each candidate keep: what it is, where you saw it (file and line, shown to
the user only), how many times, and your confidence.

Do not treat a name as sensitive just because it looks like it. `token` in a
pagination cursor, `key` in a map key and `name` of a product are common false
positives.

### 4. Ask about everything uncertain

Sort candidates into three groups:

- **Clear**: shape or field name is unmistakably sensitive, or the user said so.
- **Unsure**: could be sensitive, or masking would hurt the model's usefulness.
- **Likely noise**: looks like a lookalike.

Ask about every Unsure item, grouped so the user can answer in one pass, with
your recommendation and the reason. Do not promote an Unsure item to a rule on
your own. Show Clear items too, as a list to approve; the user has the last word.

### 5. Write the ruleset

- One file per theme (`org-hosts.yaml`, `org-fields.yaml`), id `org/...` or the
  user's chosen namespace, each rule with a `description`.
- Prefer `keys:` for field names and `values_file:` for long literal lists.
  Use `pattern:` only for a real shape, as narrow as it can be, with `allow:`
  for known lookalikes.
- Show the path and the file to the user before writing, then write it.

### 6. Verify with real samples

- Build test input from the sources the user pointed at: lines that should be
  masked, and lines that look similar but should not.
- Run `llmsp rules test [-profile NAME] FILE` and compare line by line: every
  expected value masked, nothing else.
- Report misses and false positives, fix the rule (narrow the pattern, add
  `allow:`, split the rule), and run again. Repeat until the user agrees.
- Test the user's `config.yaml` selection, not only the new file: run it with
  `-profile` for each profile the rules are meant for.

### 7. Hand over

Tell the user:

- the files written and the `rulesets.enable` / `disable` lines to add to
  `config.yaml` (or to a profile), as a suggestion, and make the edit only if
  asked;
- to restart llmsp, because rules are read at start-up, then check with
  `llmsp rules list`;
- what was left out on purpose (Unsure items answered "no", noise), so it can be
  revisited;
- that real-name rule files must not be committed to a public repository, and
  that a team can share them through a private repo in `rulesets.dirs`.

## Do not

- Do not add real values, paths or counts from the user's environment to this
  repository or to anything public.
- Do not send file contents to an external service to classify them.
- Do not edit `config.yaml`, `master.key` or `llmsp.db` without being asked;
  never read or print `master.key` or the database.
- Do not weaken or replace a `builtin/*` ruleset to hide a false positive; add
  an `allow:` pattern or an allowlist entry instead.
