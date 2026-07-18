#!/usr/bin/env bash
# gorelease one module against its latest published tag, appending the report
# to the job summary. Report-only while the modules are 0.x: the changelog's
# own policy allows breaking changes between 0.x minors, and a hard gate would
# deadlock intended breakage (the base tag can only move after the merge it
# would be gating). An incompatible change surfaces as a workflow warning so
# it is a reviewed decision, not an accident. Flip to a failing gate at v1.0.
#
# usage: apicompat.sh <module-dir> <tag-prefix>
#   core:          apicompat.sh . ''
#   nested module: apicompat.sh secmem-crypto 'secmem-crypto/'
set -u
dir="$1"
prefix="$2"
: "${GITHUB_STEP_SUMMARY:=/dev/null}"

pattern="${prefix}v*"
base=$(git tag --list "$pattern" --sort=-v:refname | head -1)
if [ -z "$base" ]; then
  echo "no ${pattern} tag published yet — nothing to compare against" |
    tee -a "$GITHUB_STEP_SUMMARY"
  exit 0
fi
# Nested-module tags are prefixed (secmem-crypto/v0.1.0); gorelease takes the
# bare module version.
version="${base#"$prefix"}"
mod=$(cd "$dir" && GOWORK=off go list -m)

report=$(mktemp)
(cd "$dir" && GOWORK=off gorelease -base="$version") >"$report" 2>&1
status=$?

{
  echo "### \`${mod}\` vs \`${base}\`"
  echo '```'
  cat "$report"
  echo '```'
} >>"$GITHUB_STEP_SUMMARY"
cat "$report"

if grep -qi "incompatible" "$report"; then
  echo "::warning title=API break in ${mod} vs ${base}::Exported API changed incompatibly. Intended? Record it in CHANGELOG.md — the next tag must bump accordingly."
elif [ $status -ne 0 ]; then
  # Non-zero without an incompatibility report means the tool itself failed
  # (auth, resolution, parse) — that must be loud, not silently green.
  echo "::error title=gorelease failed for ${mod}::exit ${status} — see log"
  exit 1
fi
exit 0
