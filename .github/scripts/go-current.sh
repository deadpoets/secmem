#!/usr/bin/env bash
# Keep every Go toolchain this repository builds with on the newest patch of
# the two releases upstream supports, and the same one everywhere.
#
# usage: go-current.sh [--local] [--offline]
#   (none)      the pins agree with each other and with go.dev     — CI
#   --local     ...and the go that runs in this checkout is the pin — release.sh
#   --offline   skip go.dev; with --local, the pre-push hook
#
# # Why
#
# Go security fixes ship as patch releases, and a stale toolchain carries every
# advisory fixed since. The vuln job only reports the ones this code reaches,
# and only on a run that happens after the advisory is published: GO-2026-6809
# (crypto/x509, reachable from secmem-crypto) was public for a day while every
# check on every open PR stayed green from runs made before it. So currency is
# checked against go.dev directly, not inferred from the advisory database.
#
# The pin lives in several places — ci.yml's two values, the copies in
# fuzz.yml and forks.yml, and a `toolchain` line in every go.mod (which is what
# makes a local `go` and CodeQL switch to the pinned release by themselves) —
# and a pin site nobody checks is a pin site that rots. ci.yml is the source;
# everything else must equal it.
#
# A local toolchain that differs from CI is the other half: a test that passes
# on one patch and fails on another is exactly what this repository's
# toolchain-coupled proofs exist to catch, and release.sh's `go test` is the
# last run before a version becomes permanent.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

local_check=0 offline=0
for arg in "$@"; do
  case "$arg" in
    --local) local_check=1 ;;
    --offline) offline=1 ;;
    *) echo "usage: go-current.sh [--local] [--offline]" >&2; exit 2 ;;
  esac
done

fail=0
bad() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }
ok() { printf '  ok    %s\n' "$1"; }

pin() { sed -nE "s/^  $2: \"([0-9.]+)\"\$/\1/p" "$1"; }
cur=$(pin .github/workflows/ci.yml GO_VERSION)
old=$(pin .github/workflows/ci.yml GO_VERSION_OLDSTABLE)
if [ -z "$cur" ] || [ -z "$old" ]; then
  echo "go-current: cannot read GO_VERSION / GO_VERSION_OLDSTABLE from ci.yml" >&2
  exit 2
fi
minor() { echo "$1" | cut -d. -f1,2; }

# --- every pin site agrees with ci.yml --------------------------------------
for wf in .github/workflows/fuzz.yml .github/workflows/forks.yml; do
  got=$(pin "$wf" GO_VERSION)
  [ "$got" = "$cur" ] && ok "$wf GO_VERSION $got" || bad "$wf GO_VERSION is '$got', ci.yml says $cur"
done
for mod in $(git ls-files | grep -E '(^|/)go\.mod$'); do
  tc=$(sed -nE 's/^toolchain go([0-9.]+)$/\1/p' "$mod")
  [ "$tc" = "$cur" ] && ok "$mod toolchain go$tc" || bad "$mod toolchain is 'go$tc', want go$cur"
  # The modules' floor is the oldstable minor (CLAUDE.md, CI section).
  gd=$(sed -nE 's/^go ([0-9.]+)$/\1/p' "$mod")
  [ "$(minor "$gd")" = "$(minor "$old")" ] && ok "$mod go $gd" ||
    bad "$mod go directive is $gd, want the oldstable minor $(minor "$old")"
done

# --- the pins are the newest releases ---------------------------------------
if [ "$offline" -eq 0 ]; then
  # Without include=all this lists exactly the supported releases, newest
  # first. Each file entry repeats "version", hence the de-duplication.
  json=$(curl -fsS --retry 3 'https://go.dev/dl/?mode=json') ||
    { echo "go-current: cannot reach go.dev" >&2; exit 2; }
  releases=$(printf '%s\n' "$json" | sed -nE 's/^ *"version": "go([0-9.]+)",?$/\1/p' | awk '!seen[$0]++')
  newest=$(printf '%s\n' "$releases" | sed -n 1p)
  second=$(printf '%s\n' "$releases" | sed -n 2p)
  if [ -z "$newest" ] || [ -z "$second" ]; then
    echo "go-current: could not parse the release list from go.dev" >&2
    exit 2
  fi
  [ "$cur" = "$newest" ] && ok "GO_VERSION $cur is the newest release" ||
    bad "GO_VERSION is $cur, newest release is $newest"
  [ "$old" = "$second" ] && ok "GO_VERSION_OLDSTABLE $old is the newest of the previous release" ||
    bad "GO_VERSION_OLDSTABLE is $old, newest of the previous release is $second"
fi

# --- the go that runs here is the pin ---------------------------------------
if [ "$local_check" -eq 1 ]; then
  # With the toolchain lines above, an older installed go switches up to the
  # pin by itself. What is left to catch: GOTOOLCHAIN=local (or a version)
  # forced in the environment, an installed go NEWER than the pin (switching
  # only goes up), and a go.work without a toolchain line of its own —
  # workspace mode takes the toolchain from go.work, not from the modules.
  for mod in $(git ls-files | grep -E '(^|/)go\.mod$'); do
    d=$(dirname "$mod")
    got=$(cd "$d" && GOWORK=off go env GOVERSION)
    [ "$got" = "go$cur" ] && ok "$d runs $got" ||
      bad "$d runs $got, want go$cur (GOTOOLCHAIN=$(go env GOTOOLCHAIN))"
  done
  if [ -f go.work ]; then
    got=$(go env GOVERSION)
    [ "$got" = "go$cur" ] && ok "go.work runs $got" ||
      bad "go.work runs $got, want go$cur — add 'toolchain go$cur' to go.work"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "go-current: the Go toolchain is not current. Move GO_VERSION and" >&2
  echo "  GO_VERSION_OLDSTABLE in ci.yml, the copies in fuzz.yml and forks.yml," >&2
  echo "  and every go.mod's toolchain line together; on a new minor release" >&2
  echo "  also raise the go directives to the new oldstable minor." >&2
  exit 1
fi
