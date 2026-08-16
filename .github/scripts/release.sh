#!/usr/bin/env bash
# Tag and publish one module, refusing to do it wrong.
#
# usage: release.sh <module-dir> <version>
#   core:          release.sh . v0.3.0
#   nested module: release.sh secmem-crypto v0.3.1
#
# Run it from anywhere in the checkout. It works out the tag name, verifies
# every precondition, shows you the tag it is about to create, and only then
# asks once for confirmation. Nothing is pushed until every check has passed.
#
# # Why this exists
#
# The release sequence has an ordering constraint that is invisible at the
# moment you get it wrong: a module's tag must be cut from a commit that
# already contains that module's go.mod, and for a dependent module that means
# AFTER the go.mod PR merges. Tag a moment early and you publish a version that
# claims a dependency it does not have. The Go module proxy and the checksum
# database are both append-only, so that version is permanent: it cannot be
# re-pointed, only superseded. secmem-crypto/v0.3.0 is exactly that mistake,
# left published because retracting it is not a thing that exists.
#
# A checklist cannot prevent this, because the failure looks identical to
# success at the keyboard. A precondition check can, because the proxy will
# tell you the version is already taken and the go.mod will tell you the commit
# is wrong. So: no checklists. Run this.
set -euo pipefail

die() { printf '\n  REFUSING: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok    %s\n' "$1"; }

[ $# -eq 2 ] || die "usage: release.sh <module-dir> <version>   e.g. release.sh secmem-crypto v0.3.1"
dir="$1"
version="$2"

cd "$(git rev-parse --show-toplevel)"
[ -d "$dir" ] || die "no such directory: $dir"

case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "version must look like v1.2.3, got: $version" ;;
esac

# The tag name is the module path suffix plus the version. Deriving it rather
# than taking it as an argument removes the chance of tagging secmem-crypto's
# version under the core's tag namespace, which would publish it as a core
# release.
if [ "$dir" = "." ]; then
  prefix=""
else
  prefix="${dir%/}/"
fi
tag="${prefix}${version}"
module=$(cd "$dir" && GOWORK=off go list -m)

printf '\nreleasing %s as %s\n\n' "$module" "$tag"

# ---------------------------------------------------------------------------
# Preconditions. Each one is a way this has gone wrong or could.
# ---------------------------------------------------------------------------

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "on branch '$branch', not main. Tags come off main."
ok "on main"

[ -z "$(git status --porcelain)" ] || die "working tree is dirty. Commit or stash first."
ok "working tree clean"

git fetch --quiet origin main
[ "$(git rev-list --count origin/main..HEAD)" = "0" ] || die "local main has commits origin/main does not. Push first."
[ "$(git rev-list --count HEAD..origin/main)" = "0" ] || die "origin/main is ahead. Run: git pull --ff-only"
ok "main matches origin/main"

git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists locally. Pick the next version."
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 && die "tag $tag already exists on origin. Pick the next version."
ok "tag $tag is free in git"

# The check that would have caught secmem-crypto/v0.3.0. Once the proxy has a
# version, that version's content is fixed forever; re-tagging produces a
# checksum mismatch for anyone who already fetched it.
escaped=$(printf '%s' "$module" | sed 's/\([A-Z]\)/!\L\1/g')
code=$(curl -s -o /dev/null -w '%{http_code}' "https://proxy.golang.org/${escaped}/@v/${version}.info" || echo "000")
case "$code" in
  404|410) ok "$version is unpublished on proxy.golang.org" ;;
  200)     die "$module@$version is ALREADY PUBLISHED on proxy.golang.org.
             The proxy and sum.golang.org are append-only, so this version can
             never be changed — only superseded by a higher one. Pick the next
             version number." ;;
  000)     die "could not reach proxy.golang.org to check whether $version is taken.
             Re-run when you have network; publishing blind is how a version
             gets burned." ;;
  *)       die "proxy.golang.org returned HTTP $code for $version — unexpected, not proceeding." ;;
esac

# The ordering check, and the reason this script exists. Every require
# directive naming a module from THIS repo must already resolve to a published
# version at the commit being tagged. That is precisely what is false when you
# tag before the dependency's go.mod PR has merged: go.mod still names the old
# version, or names a new one nobody can fetch.
#
# Parsed via `go mod edit -json` rather than by reading go.mod as text — the
# require block has several legal shapes and a regex over it is exactly the
# kind of thing that quietly matches nothing and reports success.
repo_root_module=$(GOWORK=off go list -m)
deps=$(cd "$dir" && GOWORK=off go mod edit -json | python3 -c '
import json,sys
root = sys.argv[1]
d = json.load(sys.stdin)
for r in (d.get("Require") or []):
    p = r["Path"]
    if p == root or p.startswith(root + "/"):
        print(p, r["Version"])
' "$repo_root_module")

if [ -z "$deps" ]; then
  ok "no in-repo dependencies to order against"
else
  while read -r req reqver; do
    [ -n "$req" ] || continue
    reqesc=$(printf '%s' "$req" | sed 's/\([A-Z]\)/!\L\1/g')
    rcode=$(curl -s -o /dev/null -w '%{http_code}' "https://proxy.golang.org/${reqesc}/@v/${reqver}.info" || echo "000")
    [ "$rcode" = "200" ] || die "$dir/go.mod requires $req $reqver, which is NOT published (HTTP $rcode).
             Tagging now would publish a release pointing at a version that
             cannot be resolved. Release $req $reqver first, then re-run this."
    ok "in-repo dependency $req $reqver is published"
  done <<EOF
$deps
EOF
fi

# Build and test against the RELEASED dependency graph, not the workspace. The
# workspace masks a wrong go.mod by resolving siblings from disk.
printf '  ...   building and testing %s with GOWORK=off\n' "$module"
(cd "$dir" && GOWORK=off go build ./... >/dev/null) || die "go build failed with GOWORK=off"
(cd "$dir" && GOWORK=off go test ./... >/dev/null) || die "go test failed with GOWORK=off"
ok "builds and tests against released dependencies"

# The changelog heading is NOT always the tag. Keep a Changelog numbers the
# primary module bare — "## [0.3.0]" for tag v0.3.0 — while nested modules are
# namespaced and keep the v: "## [secmem-crypto/v0.3.1]". Deriving one from the
# other is the whole reason this is a function: the first version of this check
# compared against the tag directly, which silently made a CORE release
# impossible while nested releases passed.
changelog_key() {
  if [ -z "$prefix" ]; then printf '%s' "${version#v}"; else printf '%s' "$tag"; fi
}
key=$(changelog_key)

# Locate and extract in one step, in Python, so the key is matched with
# re.escape rather than hand-rolled shell quoting. An earlier revision escaped
# the key with sed for a grep and got it wrong — the '/' in a nested tag
# terminated the s/// command, so every lookup silently reported MISSING.
# Presence and extraction are the same question; asking it twice in two
# languages was the bug.
notes=$(mktemp)
trap 'rm -f "$notes"' EXIT
# The section is WRITTEN by Python with an explicit encoding rather than
# printed to stdout: this repo is maintained from Windows, where Python's
# stdout defaults to cp1252, and CHANGELOG.md is full of em-dashes. Redirecting
# stdout there raises UnicodeEncodeError and the release notes come out either
# mangled or empty.
set +e
python3 - "$key" "$notes" <<'PY'
import re, sys
key, out = sys.argv[1], sys.argv[2]
text = open('CHANGELOG.md', encoding='utf-8').read()
start = re.search(r'^## \[' + re.escape(key) + r'\][^\n]*\n', text, re.M)
if not start:
    sys.exit(3)
body = text[start.end():]
nxt = re.search(r'^## ', body, re.M)
section = (body[:nxt.start()] if nxt else body).strip()
if not section:
    sys.exit(4)
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write(section + '\n')
PY
extract=$?
set -e
case "$extract" in
  0) ;;
  3) die "CHANGELOG.md has no '## [${key}]' entry.
             (tag is ${tag}; the primary module is numbered bare in the
             changelog — '## [0.4.0]' for tag v0.4.0 — while nested modules
             keep their full prefix.)
             Write the entry, merge it, then release." ;;
  4) die "the '## [${key}]' section is empty. A release with no notes is worse
             than no release; write the entry properly first." ;;
  *) die "failed to read CHANGELOG.md (python exit ${extract})" ;;
esac
ok "CHANGELOG.md has an entry for [$key] ($(wc -l <"$notes" | tr -d ' ') lines)"

# ---------------------------------------------------------------------------
# Confirm, then act.
# ---------------------------------------------------------------------------

printf '\n  all preconditions passed\n\n'
printf '  tag     %s\n' "$tag"
printf '  commit  %s\n' "$(git log --format='%h %s' -1)"
printf '  module  %s\n\n' "$module"

if [ "${RELEASE_YES:-}" = "1" ]; then
  printf '  RELEASE_YES=1 set, skipping confirmation\n'
elif [ -e /dev/tty ]; then
  read -r -p "  create and push this tag? [y/N] " reply </dev/tty
  case "$reply" in
    [yY]) ;;
    *) printf '\n  aborted, nothing changed\n\n'; exit 0 ;;
  esac
else
  die "no terminal to confirm on. Set RELEASE_YES=1 if you really mean it."
fi

# Annotated and signed, matching every existing tag in this repo.
git tag -a "$tag" -F - <<EOF
$module $version

See CHANGELOG.md under [$tag].

Not independently audited — see SECURITY.md.
EOF

git tag -v "$tag" >/dev/null 2>&1 || die "tag $tag did not verify after creation — not pushing"
ok "tag created and signature verifies"

git push origin "$tag"
ok "tag pushed"

# The GitHub Release. Deliberately AFTER the push and deliberately non-fatal:
# the tag is the release as far as Go is concerned, and it is already public by
# this point. Failing the script here would report an error for a release that
# actually succeeded, which is a worse outcome than a missing sidebar entry the
# maintainer can add later.
#
# --latest only for the primary module. Otherwise a nested module's patch
# release would claim the repository's "Latest" badge and a visitor would land
# on secmem-crypto instead of secmem.
if command -v gh >/dev/null 2>&1; then
  latest_flag="--latest=false"
  [ -z "$prefix" ] && latest_flag="--latest"
  if gh release create "$tag" --title "$tag" --notes-file "$notes" $latest_flag >/dev/null 2>&1; then
    ok "GitHub Release created from the CHANGELOG section"
  else
    printf '  warn  could not create the GitHub Release (tag IS published).\n'
    printf '        retry:  gh release create %s --title %s --notes-file <(section of CHANGELOG.md)\n' "$tag" "$tag"
  fi
else
  printf '  warn  gh not found; tag is published but no GitHub Release was created\n'
fi

printf '\n  published %s\n' "$tag"
printf '  note: proxy.golang.org negative-caches a version it was asked about\n'
printf '        before publication, so %s.info may 404 for a while even though\n' "$version"
printf '        the module resolves. Check with:\n'
printf '          GOPROXY=proxy.golang.org go list -m %s@%s\n\n' "$module" "$version"
