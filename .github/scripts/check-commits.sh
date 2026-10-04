#!/usr/bin/env bash
# Check a range of commits before it leaves the machine:
#
#   bash .github/scripts/check-commits.sh <range>     e.g. origin/main..HEAD
#
# The pre-push hook (install-hooks.sh) runs this on exactly the commits a push
# would publish. Every check reads the commits themselves, never the working
# tree, so it gives the same answer whichever branch is checked out — a push of
# a branch from another worktree is checked as what it is.
#
# Only checks that are fast, need no network and no compile belong here; the
# test matrix, the linters, vet across platforms and the advisory scan are
# CI's. What is here is what cannot be taken back once pushed, plus the two
# things CI would refuse anyway and that cost a full CI round to learn:
#
#   paths       agent-tooling and credential-shaped files (pre-commit's list,
#               applied again because a commit made with --no-verify, or in a
#               clone without the hooks, never met it)
#   secrets     gitleaks over every commit in the range — CI scans per commit
#               too, so a later commit that removes a finding does not clear it
#   trailers    AI attribution in a commit message (commit-msg's rule)
#   signatures  main requires signed commits; a rebase done by another tool
#               can drop them silently
#   gofmt       every Go file the range touches, as it is at the tip
set -uo pipefail

range=${1:?usage: check-commits.sh <range>}
cd "$(git rev-parse --show-toplevel)" || exit 2
tip=${range##*..}
fail=0
say() { printf 'check-commits: %s\n' "$*" >&2; }

commits=$(git rev-list --no-merges "$range") || exit 2
[ -n "$commits" ] || exit 0

# --- paths -------------------------------------------------------------------
blocked=$(git diff --name-only --diff-filter=ACMR "$range" | grep -E \
  '(^|/)\.(claude|codex|continue|cursor|opencode)/|(^|/)\.mcp\.json$|(^|/)(CLAUDE|AGENT|AGENTS|GEMINI)\.md$|(^|/)\.(cursorrules|clinerules|windsurfrules|roomodes)$|(^|/)\.env($|\.)|(^|/)(id_rsa|id_ecdsa|id_ed25519)|\.(pem|key|p12|pfx)$|(^|/)(credentials|kubeconfig|\.netrc)$' \
  || true)
if [ -n "$blocked" ]; then
  say "agent-tooling or credential paths in the range:"
  printf '%s\n' "$blocked" | sed 's/^/  /' >&2
  fail=1
fi

# --- secrets -----------------------------------------------------------------
if command -v gitleaks >/dev/null 2>&1; then
  if ! gitleaks detect --redact --no-banner --log-level=warn \
      --log-opts="--no-merges $range" >&2; then
    say "gitleaks found something in the range (it scans each commit: fix the commit that introduced it, a follow-up commit does not clear it)"
    fail=1
  fi
else
  say "gitleaks is not installed, so the range was NOT scanned for secrets."
  say "  go install github.com/zricethezav/gitleaks/v8@latest"
  fail=1
fi

# --- trailers and signatures -------------------------------------------------
for c in $commits; do
  body=$(git cat-file commit "$c")
  if printf '%s\n' "$body" | grep -qiE '^(Co-authored-by:.*(claude|anthropic|copilot|cursor))|Generated with \[?(Claude|Cursor)'; then
    say "AI attribution trailer in $(git log --format='%h %s' -1 "$c")"
    fail=1
  fi
  if ! printf '%s\n' "$body" | sed '/^$/q' | grep -q '^gpgsig'; then
    say "unsigned commit $(git log --format='%h %s' -1 "$c")"
    fail=1
  fi
done

# --- gofmt -------------------------------------------------------------------
if command -v gofmt >/dev/null 2>&1; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case $f in */testdata/*) continue ;; esac
    if [ -n "$(git show "$tip:$f" | gofmt -l 2>/dev/null)" ]; then
      say "not gofmt-clean at the tip: $f"
      fail=1
    fi
  done < <(git diff --name-only --diff-filter=ACMR "$range" -- '*.go')
else
  say "gofmt not found; formatting was not checked"
fi

exit $fail
