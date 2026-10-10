#!/usr/bin/env bash
# Fails if text contains any term from a private denylist.
#
# The denylist lives outside the repository because the list itself would
# reveal what it protects (organisation names, internal hosts, ...).
#   default:  ${XDG_CONFIG_HOME:-~/.config}/llmsp/denylist.txt
#   override: LLMSP_DENYLIST=/path/to/file
# One term per line, case-insensitive, fixed strings. Lines starting with # are ignored.
#
# Usage:
#   scripts/check-denylist.sh --staged       staged diff (pre-commit)
#   scripts/check-denylist.sh --file PATH    a file (commit-msg, PR body)
#   scripts/check-denylist.sh --range A..B   commits, authors and messages in a range
set -euo pipefail

list="${LLMSP_DENYLIST:-${XDG_CONFIG_HOME:-$HOME/.config}/llmsp/denylist.txt}"
if [[ ! -f "$list" ]]; then
  echo "denylist: $list not found; skipping (create it to enable this check)" >&2
  exit 0
fi
terms="$(grep -v '^[[:space:]]*#' "$list" | sed '/^[[:space:]]*$/d' || true)"
[[ -z "$terms" ]] && exit 0

case "${1:-}" in
  --staged) text="$(git diff --cached -U0 --no-color | grep '^+' | grep -v '^+++' || true)" ;;
  --file)   text="$(cat "$2")" ;;
  --range)  text="$(git log --format='%an <%ae>%n%cn <%ce>%n%B' "$2"; git diff -U0 --no-color "$2" | grep '^+' || true)" ;;
  *) echo "usage: $0 --staged | --file PATH | --range A..B" >&2; exit 2 ;;
esac

if hits="$(printf '%s\n' "$text" | grep -i -n -F -f <(printf '%s\n' "$terms"))"; then
  echo "denylist: found denylisted terms (matching lines shown):" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
