#!/usr/bin/env bash
# kernel-gauntlet.sh — the run a KERNELS.md row records, on the machine it
# describes.
#
#   bash .github/scripts/kernel-gauntlet.sh [out-dir]
#
# Run it from the root of a checkout, on the Linux box under test, as an
# ordinary user. It needs the pinned Go, a C compiler (for -race and -asan),
# and passwordless sudo for two things only: lifting RLIMIT_MEMLOCK where CI
# lifts it, and the root isolation lane. Without sudo those two stages are
# reported as "not run", never as passed.
#
# Every stage is one CI lane, run the way CI runs it and piped through
# internal/skipaudit against the same allowlist, so a proof that stops
# running on this kernel fails the stage instead of vanishing:
#
#   race           core, secmem-crypto, secmem-lint under -race
#   runtimesecret  core and secmem-crypto with GOEXPERIMENT=runtimesecret
#   noescape       TestNoHeapEscape (core); secmem-crypto without -race
#   asan           core and secmem-crypto under -asan
#   residue        the out-of-process key residue scan
#   root           isolation, extraction and madvise proofs as root
#   proofs         the three counted proofs, verbosely
#
# By default secmem-crypto is tested against the core IN THIS TREE (a go.work
# is written, as CI's setup-workspace does), which is what a pre-release run
# wants. GAUNTLET_RELEASED=1 tests it against the core its go.mod names, the
# way a consumer builds it; use that on a checkout of a released tag.
#
# It prints a stage table and a draft KERNELS.md row, and leaves every log in
# the output directory. It exits non-zero if any stage failed. The row is a
# draft: a human reads the logs before it goes in the file.

set -uo pipefail

[ "$(uname -s)" = Linux ] || { echo "kernel-gauntlet: Linux only" >&2; exit 2; }
[ -f go.mod ] && [ -d secmem-crypto ] && [ -d .github/skip-allowlist ] ||
  { echo "kernel-gauntlet: run from the root of a secmem checkout" >&2; exit 2; }

root=$PWD
out=${1:-"$root/gauntlet-$(uname -r)-$(date -u +%Y%m%dT%H%M%SZ)"}
mkdir -p "$out"
out=$(cd "$out" && pwd)
allow="$root/.github/skip-allowlist"

export GOFLAGS="${GOFLAGS:-} -buildvcs=false"
if [ "${GAUNTLET_RELEASED:-0}" = 1 ]; then
  export GOWORK=off
  mode="secmem-crypto against the released core its go.mod names"
else
  work="$out/go.work"
  rm -f "$work" "$work.sum"
  (cd "$out" && go work init "$root" "$root/secmem-crypto" "$root/secmem-lint") || exit 2
  export GOWORK="$work"
  mode="secmem-crypto against the core in this tree"
fi

have_sudo=0
sudo -n true 2>/dev/null && have_sudo=1

go build -o "$out/skipaudit" ./internal/skipaudit || { echo "kernel-gauntlet: cannot build skipaudit" >&2; exit 2; }

{
  echo "date:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit:    $(git rev-parse HEAD 2>/dev/null || echo unknown) $(git describe --tags --always --dirty 2>/dev/null || true)"
  echo "mode:      $mode"
  echo "kernel:    $(uname -srm)"
  echo "os:        $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
  echo "cpu:       $(grep -m1 -E '^(model name|Model|Hardware)' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//') x$(nproc)"
  echo "virt:      $(systemd-detect-virt 2>/dev/null || echo unknown)"
  echo "go:        $(go version)"
  echo "cc:        $( (${CC:-cc} --version 2>/dev/null || echo none) | head -1)"
  echo "user:      $(id -un) uid=$(id -u), sudo=$have_sudo"
  echo "memlock:   soft $(ulimit -Sl) KiB, hard $(ulimit -Hl) KiB"
  echo "secretmem: $(grep -h CONFIG_SECRETMEM "/boot/config-$(uname -r)" 2>/dev/null || echo 'config not readable')"
  echo "cmdline:   $(cat /proc/cmdline)"
  echo "lockdown:  $(cat /sys/kernel/security/lockdown 2>/dev/null || echo n/a)"
  echo "ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo n/a)"
} > "$out/env.txt"
cat "$out/env.txt"

go test -count=1 -run TestReportEnvironment -v . > "$out/report-environment.txt" 2>&1
probe=$(grep -m1 -o 'Probe: .*' "$out/report-environment.txt" | sed 's/^Probe: //')
echo "probe:     ${probe:-not reported}" | tee -a "$out/env.txt"
echo

names=() results=()
record() { names+=("$1"); results+=("$2"); printf '%-28s %s\n' "$1" "$2"; }

# audited <stage> <dir> <allowlist> <memlock: keep|unlimited> <go test args...>
audited() {
  local stage=$1 dir=$2 list=$3 memlock=$4
  shift 4
  if [ "$memlock" = unlimited ] && [ "$have_sudo" = 0 ]; then
    record "$stage" "NOT RUN (needs sudo to lift RLIMIT_MEMLOCK, as CI does)"
    return
  fi
  (
    cd "$root/$dir" || exit 2
    if [ "$memlock" = unlimited ]; then
      sudo -n prlimit --pid "$BASHPID" --memlock=unlimited:unlimited || exit 2
    fi
    echo "memlock soft/hard: $(ulimit -Sl) / $(ulimit -Hl)"
    go test "$@" -json ./... | "$out/skipaudit" -allow "$allow/$list.txt"
  ) > "$out/$stage.log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then record "$stage" PASS; else record "$stage" "FAIL (exit $rc, see $stage.log)"; fi
}

audited race-core            .             linux keep      -count=1 -race
audited race-crypto          secmem-crypto linux unlimited -count=1 -race
audited race-lint            secmem-lint   linux keep      -count=1 -race
(
  export GOEXPERIMENT=runtimesecret
  audited runtimesecret-core   .             linux keep      -count=1
  audited runtimesecret-crypto secmem-crypto linux unlimited -count=1 -skip '^(TestKeyResidue|TestResidue)'
  printf '%s\n' "${names[@]}" > "$out/.names.rs"; printf '%s\n' "${results[@]}" > "$out/.results.rs"
)
# The subshell kept GOEXPERIMENT from leaking; pick its two results back up.
mapfile -t rs_n < "$out/.names.rs"; mapfile -t rs_r < "$out/.results.rs"
names=("${rs_n[@]}"); results=("${rs_r[@]}"); rm -f "$out/.names.rs" "$out/.results.rs"

audited noescape-core        .             linux keep      -count=1 -run TestNoHeapEscape
audited noescape-crypto      secmem-crypto linux unlimited -count=1 -skip '^(TestKeyResidue|TestResidue)'
audited asan-core            .             linux keep      -count=1 -asan
audited asan-crypto          secmem-crypto linux unlimited -count=1 -asan -skip '^(TestKeyResidue|TestResidue)'
audited residue              secmem-crypto linux-residue unlimited -count=1 -run '^(TestKeyResidue|TestResidue)'

# The root lane: the binary is built unprivileged and only it runs as root.
if [ "$have_sudo" = 1 ]; then
  (
    cd "$root" && GOWORK=off go test -c -o "$out/secmem.test" . &&
      sudo -n "$out/secmem.test" -test.v=test2json -test.count=1 -test.run 'Extraction|Isolation|MemfdSecret|Madvise' |
      go tool test2json -t -p github.com/deadpoets/secmem |
        "$out/skipaudit" -allow "$allow/linux-root.txt"
  ) > "$out/root.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then record root PASS; else record root "FAIL (exit $rc, see root.log)"; fi
else
  record root "NOT RUN (needs sudo)"
fi

# The three counted proofs, verbosely, so the row can say n/3 and why.
(cd "$root" && go test -count=1 -v -run 'TestGuardPages|TestCanary|TestMemfdIsolation|TestAllocMemfdSecret' .) > "$out/proofs.log" 2>&1
proof() { # name pattern -> pass | skip | fail | absent
  local lines
  lines=$(grep -E -- "^--- (PASS|FAIL|SKIP): ($2)" "$out/proofs.log" || true)
  if [ -z "$lines" ]; then echo absent
  elif grep -q '^--- FAIL' <<<"$lines"; then echo fail
  elif grep -q '^--- PASS' <<<"$lines"; then echo pass
  else echo skip; fi
}
p_guard=$(proof guard 'TestGuardPages')
p_memfd=$(proof memfd 'TestMemfdIsolation')
p_canary=$(proof canary 'TestCanary')
n=0
for p in "$p_guard" "$p_memfd" "$p_canary"; do [ "$p" = pass ] && n=$((n + 1)); done
record proofs "guard-fault=$p_guard memfd-isolation=$p_memfd canary=$p_canary ($n/3)"

failed=0 notrun=0
for r in "${results[@]}"; do
  case $r in FAIL*) failed=$((failed + 1)) ;; "NOT RUN"*) notrun=$((notrun + 1)) ;; esac
done
case "$p_guard$p_memfd$p_canary" in *fail* | *absent*) failed=$((failed + 1)) ;; esac

if grep -q 'memfd_secret' <<<"${probe%%missing:*}"; then secretmem=live; else secretmem=fallback; fi
if [ $failed -gt 0 ]; then verdict="FAIL"; elif [ $notrun -gt 0 ]; then verdict="INCOMPLETE"; else verdict="PASS"; fi

{
  echo
  for i in "${!names[@]}"; do printf '%-28s %s\n' "${names[$i]}" "${results[$i]}"; done
  echo
  echo "Draft KERNELS.md row (read the logs first):"
  echo "| $(date -u +%Y-%m-%d) | $(uname -r) | $(go env GOARCH) | <environment> | $secretmem | $verdict · $n/3 |"
} > "$out/summary.txt"
echo
tail -n 3 "$out/summary.txt"
echo "logs: $out"
[ $failed -eq 0 ]
