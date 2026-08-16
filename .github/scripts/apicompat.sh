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

# Classify the outcome. gorelease exits non-zero for several reasons that are
# not "the tool broke", and the original version treated every one of them as a
# tool failure. That produces a red check nobody can act on, which is how a
# check first gets ignored and then gets deleted — so the classification matters
# as much as the check.
#
# Two of these were observed in one week:
#
#   - Transient module resolution. Publishing a version puts it on the git
#     remote immediately but on proxy.golang.org and sum.golang.org only after a
#     propagation delay. In that window any `go` command that resolves the
#     module 404s. This module now carries a `retract` directive, which makes it
#     WORSE: retractions live in the LATEST version's go.mod, so every
#     resolution path must fetch exactly the version that was just published.
#     Every PR opened during the window fails, on content that has nothing to do
#     with it. Not retried here — the window is minutes to tens of minutes, far
#     longer than a job should sit spinning.
#
#   - "Cannot suggest a release version". A legitimate gorelease result, not an
#     error: it declines when the base is not the most recent version of the
#     major, which is exactly the state a dependency floor-raise PR is in. This
#     is the same deadlock the header describes for API breaks, and it deserves
#     the same treatment.
#
# Anything else non-zero is still loud. A parse error, a missing tool, or an
# auth failure must not pass silently.
#
# The transient bucket does also swallow a genuinely unresolvable module graph —
# a deleted upstream dependency and a propagation lag produce the same 404. That
# is accepted rather than overlooked: an unresolvable graph fails `go build` and
# `go test` in the test, cross-compile and examples jobs, all of which are
# required checks. apicompat is report-only and is not the control that catches
# it, so downgrading resolution failures here loses no coverage.
transient_re='unknown revision|404 Not Found|reading https://(proxy|sum)\.golang\.org|dial tcp|connection reset|i/o timeout|TLS handshake timeout|no such host'

# Match the section header and summary lines gorelease actually emits
# ("## incompatible changes", "There are incompatible changes.", "Incompatible
# changes were detected.") — NOT the bare word. A bare match also hits the
# "+incompatible" suffix Go puts on pre-modules major versions, so a genuine
# tool error whose output happened to name such a dependency would have been
# reported as an API break and its real cause lost.
if grep -qi "incompatible changes" "$report"; then
  echo "::warning title=API break in ${mod} vs ${base}::Exported API changed incompatibly. Intended? Record it in CHANGELOG.md — the next tag must bump accordingly."
elif [ $status -eq 0 ]; then
  : # clean comparison
elif grep -qEi "$transient_re" "$report"; then
  echo "::warning title=apicompat skipped for ${mod}::Module resolution failed transiently — a version published minutes ago has not reached proxy.golang.org/sum.golang.org yet. Re-run once it propagates; this is not an API finding."
elif grep -qi "cannot suggest a release version" "$report"; then
  echo "::warning title=apicompat inconclusive for ${mod}::gorelease declined to suggest a version against base ${base}. Expected while a dependency floor-raise is in flight; the API diff above is still valid."
else
  echo "::error title=gorelease failed for ${mod}::exit ${status} — see log"
  exit 1
fi
exit 0
