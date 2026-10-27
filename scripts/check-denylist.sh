#!/usr/bin/env bash
# Fails if text contains any term from a private denylist.
#
# The denylist lives outside the repository because the list itself would
# reveal what it protects (organisation names, internal hosts, ...).
#   default:  ${XDG_CONFIG_HOME:-~/.config}/llmsp/denylist.txt
#   override: LLMSP_DENYLIST=/path/to/file (must exist when set)
#   The check is skipped when the default file is missing.
# One term per line, case-insensitive, fixed strings. Lines starting with # are ignored.
#
# Usage:
#   scripts/check-denylist.sh --staged       staged diff, file names and identity (pre-commit)
#   scripts/check-denylist.sh --file PATH    a file (commit-msg, PR body)
#   scripts/check-denylist.sh --range A..B   commits, authors, messages and file names in a range
set -euo pipefail

list="${LLMSP_DENYLIST:-${XDG_CONFIG_HOME:-$HOME/.config}/llmsp/denylist.txt}"
if [[ ! -f "$list" ]]; then
  # An explicitly named list that is missing is a mistake, not an opt-out.
  if [[ -n "${LLMSP_DENYLIST:-}" ]]; then
    echo "denylist: LLMSP_DENYLIST=$list not found" >&2
    exit 1
  fi
  echo "denylist: $list not found; skipping (create it to enable this check)" >&2
  exit 0
fi
terms="$(tr -d '\r' <"$list" | grep -v '^[[:space:]]*#' | sed '/^[[:space:]]*$/d' || true)"
[[ -z "$terms" ]] && exit 0

# Added lines only: skip the per-file headers (+++ b/path) but keep content
# lines that happen to start with "++".
added() { awk '/^diff --git /{h=0} /^@@/{h=1; next} h && /^\+/'; }

case "${1:-}" in
  --staged) text="$(git var GIT_AUTHOR_IDENT; git var GIT_COMMITTER_IDENT
                    git -c core.quotePath=false diff --cached --name-only
                    git diff --cached -U0 --no-color | added)" ;;
  --file)   text="$(cat "$2")" ;;
  --range)  text="$(git log --format='%an <%ae>%n%cn <%ce>%n%B' "$2"
                    git -c core.quotePath=false log --format= --name-only "$2"
                    git log --format= -p -U0 --no-color "$2" | added)" ;;
  *) echo "usage: $0 --staged | --file PATH | --range A..B" >&2; exit 2 ;;
esac

if hits="$(printf '%s\n' "$text" | grep -i -n -F -f <(printf '%s\n' "$terms"))"; then
  echo "denylist: found denylisted terms (matching lines shown):" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
