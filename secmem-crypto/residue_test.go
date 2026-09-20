//go:build (linux || windows) && (amd64 || arm64) && !race

// Out-of-process key residue proof. For every entry point that holds or
// derives a secret, a victim subprocess receives known key material straight
// into a SecureBuffer, builds the object, uses it, and is frozen at each
// phase while this process — its parent — reads every readable page of its
// address space and counts the key's encodings found outside locked memory.
// The encodings are not just the raw key: they include what the
// implementation derives from it and would leak it just as well (see
// residue_scenarios_test.go).
//
// This file is the part that does not depend on the operating system: the
// victim protocol, the phases each class asserts, and the pattern matching.
// Freezing the victim, enumerating its mappings, learning which of them the
// kernel reports as locked, and reading them are per-OS and live in
// residue_linux_test.go and residue_windows_test.go.
//
// The class each scenario asserts is the README's classification, measured
// rather than argued. A contained entry point leaves nothing outside locked
// memory before, between or after operations; a transient one leaves copies
// on every use, which is asserted too — if the standard library ever stops
// making them, this test fails and the docs are due a rewrite, not a looser
// assertion — and on a GOEXPERIMENT=runtimesecret build those copies must be
// gone after enough GC cycles.
//
// Robustness: every scan must also find a heap canary the victim keeps alive
// on purpose, so a scan that silently reads nothing fails instead of passing.
// The environment can refuse the scan (no ptrace permission, no lockable
// memory); that skips unprivileged and fails as root, like the extraction
// proof in the core module. It is excluded under -race, whose shadow
// mappings are terabytes of reservation, and on 386, which runtime/secret
// does not support; CI runs it in its own non-race job on linux/amd64,
// linux/arm64 (once per build mode) and windows/amd64.

package secmemcrypto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deadpoets/secmem"
)

const (
	residueVictimEnv = "SECMEMCRYPTO_RESIDUE_VICTIM"
	residueAuxEnv    = "SECMEMCRYPTO_RESIDUE_AUX"

	// residueMemlockBudget is what the victim asks for before it locks
	// anything: the Argon2 workspace scenario needs more than the default
	// Windows working-set minimum allows, and raising it at startup is what a
	// program using these APIs does (see argon2_workspace_test.go). A budget
	// it cannot reach is not fatal here — the allocation that then fails
	// skips the scenario with the platform's own reason.
	residueMemlockBudget = 64 << 20

	// residueSettleRounds bounds how many GC cycles a runtimesecret build
	// gets to erase a transient scenario's copies. ECDSA's cached FIPS-form
	// key needs two: one to find the transient key unreachable and run its
	// cleanup, one to collect the evicted entry.
	residueSettleRounds = 12
)

// residueCanary is the victim's always-live heap marker. It is derived, never
// a literal, so it cannot sit in the binary's read-only data, and it is not
// secret: the parent must find it in every scan or the scan proves nothing.
func residueCanary() []byte {
	b := make([]byte, 48)
	for i := range b {
		b[i] = 0x5A ^ byte(i*13+7)
	}
	return b
}

var residueCanaryKeep []byte

// TestKeyResidueVictim is the victim subprocess. It does nothing in an
// ordinary run and assumes the role only when re-executed by
// TestKeyResidue with residueVictimEnv set.
//
// Protocol, on stdin: a big-endian uint32 length and that many secret bytes,
// read straight into a SecureBuffer, then one command byte at a time —
// c(onstruct), o(perate), g(c round), d(estroy), q(uit). Every reply is one
// stdout line: READY <pid>, OK <command>, SKIP <reason>, or ERR <reason>.
// Nothing is read through a buffered reader, so no secret byte can be read
// ahead onto the heap.
func TestKeyResidueVictim(t *testing.T) {
	name := os.Getenv(residueVictimEnv)
	if name == "" {
		return
	}
	reply := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
		_ = os.Stdout.Sync()
	}
	fail := func(err error) {
		reply("ERR %s", strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(3)
	}
	sc, ok := residueScenarioByName(name)
	if !ok {
		fail(fmt.Errorf("unknown scenario %q", name))
	}
	aux, err := hex.DecodeString(os.Getenv(residueAuxEnv))
	if err != nil {
		fail(err)
	}

	var n [4]byte
	if _, err := io.ReadFull(os.Stdin, n[:]); err != nil {
		fail(err)
	}
	buf, err := secmem.NewEmptyBuffer(int(binary.BigEndian.Uint32(n[:])))
	if err != nil {
		reply("SKIP no lockable memory for the secret: %v", err)
		os.Exit(0)
	}
	if err := buf.WithBytesErr(func(p []byte) error {
		_, e := io.ReadFull(os.Stdin, p)
		return e
	}); err != nil {
		fail(err)
	}
	_, _ = secmem.EnsureMemlockLimit(residueMemlockBudget)
	residueCanaryKeep = residueCanary()
	reply("READY %d", os.Getpid())

	var (
		op      func() error
		destroy func() error
	)
	var cmd [1]byte
	for {
		if _, err := os.Stdin.Read(cmd[:]); err != nil {
			os.Exit(0)
		}
		switch cmd[0] {
		case 'c':
			op, destroy, err = sc.victim(buf, aux)
			if errors.Is(err, secmem.ErrNoSecureMemory) {
				reply("SKIP no lockable memory for the scenario: %v", err)
				os.Exit(0)
			}
			if err != nil {
				fail(fmt.Errorf("construct: %w", err))
			}
			runtime.GC()
			runtime.GC()
		case 'o':
			for i := range sc.ops() {
				if err := op(); err != nil {
					fail(fmt.Errorf("operation %d: %w", i, err))
				}
			}
		case 'g':
			runtime.GC()
			time.Sleep(10 * time.Millisecond) // let cleanups queued by that cycle run
		case 'd':
			if err := destroy(); err != nil {
				fail(fmt.Errorf("destroy: %w", err))
			}
			runtime.GC()
			runtime.GC()
		case 'q':
			os.Exit(0)
		default:
			fail(fmt.Errorf("unknown command %q", cmd[0]))
		}
		reply("OK %c", cmd[0])
	}
}

func TestKeyResidue(t *testing.T) {
	if os.Getenv(residueVictimEnv) != "" {
		t.Skip("running as a victim")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtimesecret=%v euid=%d core=%q", secmem.RuntimeSecretActive(), os.Geteuid(), coreReleaseVersion())
	for _, sc := range residueScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			runResidueScenario(t, exe, sc)
		})
	}
}

// coreReleaseVersion is the released version of the core module this
// package resolves, or "" when it resolves a local or workspace tree, whose
// behaviour is whatever this checkout says. Test binaries carry no module
// build info, so it asks the go tool, as the fork identity tests do; without
// one it reports "" and every scenario runs.
func coreReleaseVersion() string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{if .Replace}}{{else}}{{.Version}}{{end}}", "github.com/deadpoets/secmem").Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if _, ok := releaseTriple(v); !ok {
		return "" // a workspace module has no version; a pseudo-version is not a release
	}
	return v
}

// releaseTriple parses a plain release version "vX.Y.Z"; pre-releases and
// pseudo-versions are not releases and do not parse.
func releaseTriple(v string) ([3]int, bool) {
	var t [3]int
	rest, ok := strings.CutPrefix(v, "v")
	if !ok {
		return t, false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return t, false
		}
		t[i] = n
	}
	return t, true
}

// releaseBefore reports whether release v is older than release min.
func releaseBefore(v, minimum string) bool {
	a, _ := releaseTriple(v)
	b, _ := releaseTriple(minimum)
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// residueVictim is a running victim process.
type residueVictim struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
	errb  *bytes.Buffer
	pid   int
}

func (v *residueVictim) line() string {
	v.t.Helper()
	s, err := v.out.ReadString('\n')
	if err != nil {
		v.t.Fatalf("victim exited (%v); stderr:\n%s", err, v.errb.String())
	}
	return strings.TrimSpace(s)
}

// do sends one command and waits for its acknowledgement; a SKIP from the
// victim (an environment that cannot lock the scenario's memory) skips.
func (v *residueVictim) do(c byte) {
	v.t.Helper()
	if _, err := v.stdin.Write([]byte{c}); err != nil {
		v.t.Fatalf("send %q: %v; stderr:\n%s", c, err, v.errb.String())
	}
	for {
		s := v.line()
		switch {
		case s == "OK "+string(c):
			return
		case strings.HasPrefix(s, "SKIP "):
			residueEnvironmental(v.t, "%s", s[5:])
		case strings.HasPrefix(s, "ERR "):
			v.t.Fatalf("victim %q: %s", c, s[4:])
		}
		// anything else is test-framework chatter; keep reading
	}
}

// residueEnvironmental skips for a condition the environment imposes, except
// as root, which nothing may refuse.
func residueEnvironmental(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatalf("as root: "+format, args...)
	}
	t.Skipf(format, args...)
}

func startResidueVictim(t *testing.T, exe, name string, secret, aux []byte) *residueVictim {
	t.Helper()
	cmd := exec.Command(exe, "-test.run=^TestKeyResidueVictim$", "-test.count=1")
	cmd.Env = append(os.Environ(), residueVictimEnv+"="+name, residueAuxEnv+"="+hex.EncodeToString(aux))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	v := &residueVictim{t: t, cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout), errb: new(bytes.Buffer)}
	cmd.Stderr = v.errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		residueThaw(cmd.Process.Pid)
		_, _ = stdin.Write([]byte{'q'})
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	msg := make([]byte, 4+len(secret))
	binary.BigEndian.PutUint32(msg, uint32(len(secret)))
	copy(msg[4:], secret)
	if _, err := stdin.Write(msg); err != nil {
		t.Fatalf("send secret: %v", err)
	}
	for {
		s := v.line()
		if strings.HasPrefix(s, "SKIP ") {
			residueEnvironmental(t, "%s", s[5:])
		}
		if strings.HasPrefix(s, "ERR ") {
			t.Fatalf("victim: %s", s[4:])
		}
		if pid, ok := strings.CutPrefix(s, "READY "); ok {
			v.pid, err = strconv.Atoi(pid)
			if err != nil {
				t.Fatalf("parse %q: %v", s, err)
			}
			return v
		}
	}
}

func runResidueScenario(t *testing.T, exe string, sc residueScenario) {
	if v := coreReleaseVersion(); sc.minCore != "" && v != "" && releaseBefore(v, sc.minCore) {
		t.Skipf("this module resolves core %s; the scenario's class depends on behaviour first released in %s", v, sc.minCore)
	}
	class := sc.class
	if sc.needsPreemptSuppression && !secmem.Probe().AsyncPreemptSuppressed {
		class = residueControlSpill
		t.Logf("Scrub does not suppress asynchronous preemption on %s, so this scenario asserts the spill class: the copies are expected", runtime.GOOS)
	}
	secret, aux, pats := sc.material(t)
	v := startResidueVictim(t, exe, sc.name, secret, aux)
	rs := secmem.RuntimeSecretActive()

	none := func(phase string, r residueScan) {
		t.Helper()
		if r.unlocked() > 0 {
			t.Errorf("%s: %s found outside locked memory: %s", sc.name, phase, r)
		}
	}
	some := func(phase, why string, r residueScan) {
		t.Helper()
		if r.unlocked() == 0 {
			t.Errorf("%s: %s: nothing found outside locked memory, but %s — if that is now true, the classification and its docs need rewriting, not this assertion", sc.name, phase, why)
		}
	}

	r := scanResidue(t, v.pid, pats)
	t.Logf("loaded:      %s", r)
	none("the intake", r) // every class: the secret reached the buffer without touching the heap

	v.do('c')
	r = scanResidue(t, v.pid, pats)
	t.Logf("constructed: %s", r)
	if class == residueContained {
		none("construction", r)
	}

	v.do('o')
	r = scanResidue(t, v.pid, pats)
	t.Logf("used:        %s", r)
	switch class {
	case residueContained:
		none("use", r)
	case residueTransient:
		some("use", "this entry point is classified transient: every operation copies the key through the heap", r)
	case residueControlScrub, residueControlPlain, residueControlSpill:
		some("use", "the control puts a copy of the secret outside locked memory on every operation", r)
	}

	// Settle: GC cycles, scanning after each.
	for round := 1; round <= residueSettleRounds; round++ {
		v.do('g')
		r = scanResidue(t, v.pid, pats)
		if r.unlocked() == 0 || round == residueSettleRounds || (!rs && round == 2) {
			t.Logf("after %2d GC: %s", round, r)
			break
		}
	}
	switch {
	case class == residueContained:
		none("after GC", r)
	case class == residueControlPlain:
		some("after GC", "a heap copy made outside Scrub is never erased by the runtime, on any build", r)
	case class == residueControlSpill:
		// Not asserted: a spill made outside any Scrub window is not the
		// runtime's to erase, and whether it outlives GC depends on what
		// reuses that stack.
	case rs:
		// runtime/secret erases allocations made inside Scrub once the
		// collector finds them unreachable; that is the whole of its promise.
		none(fmt.Sprintf("after %d GC cycles on a runtimesecret build", residueSettleRounds), r)
	case class == residueControlScrub:
		some("after GC", "a legacy build has no runtime erasure, so a dropped heap copy survives the collector", r)
	}

	v.do('d')
	r = scanResidue(t, v.pid, pats)
	t.Logf("destroyed:   %s", r)
	if r.locked > 0 {
		t.Errorf("%s: after Destroy the secret is still in locked memory: %s", sc.name, r)
	}
	if class == residueContained {
		none("after Destroy", r)
	}
}

// residuePattern is one encoding of a secret. Patterns are matched through
// two 16-byte windows — the head, and a tail aligned to 8 bytes so a
// word-swapped or limb-reversed encoding still lines up — so a copy that
// survived only in part is still counted.
type residuePattern struct {
	label string
	b     []byte
}

type residueWindow struct {
	label string
	w     []byte
}

func residueWindows(pats []residuePattern) ([]residueWindow, error) {
	var ws []residueWindow
	for _, p := range pats {
		if len(p.b) < 16 {
			return nil, fmt.Errorf("pattern %s is %d bytes; 16 is the minimum that cannot match by chance", p.label, len(p.b))
		}
		if isLowEntropy(p.b[:16]) {
			return nil, fmt.Errorf("pattern %s has a low-entropy head that would match unrelated memory", p.label)
		}
		ws = append(ws, residueWindow{p.label, p.b[:16]})
		if tail := (len(p.b) - 16) / 8 * 8; tail >= 16 {
			if isLowEntropy(p.b[tail : tail+16]) {
				return nil, fmt.Errorf("pattern %s has a low-entropy tail that would match unrelated memory", p.label)
			}
			ws = append(ws, residueWindow{p.label, p.b[tail : tail+16]})
		}
	}
	return ws, nil
}

// isLowEntropy rejects windows with fewer than 10 distinct byte values: a
// random 16-byte window has about 15, and a constant pad or a zero-padded
// limb has 1 or 2 — those would count unrelated memory as a leak.
func isLowEntropy(w []byte) bool {
	var seen [256]bool
	n := 0
	for _, c := range w {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n < 10
}

type residueScan struct {
	byLabel map[string]int
	locked  int
	readMiB int
}

func (r residueScan) unlocked() int {
	n := 0
	for _, c := range r.byLabel {
		n += c
	}
	return n
}

func (r residueScan) String() string {
	if r.unlocked() == 0 {
		return fmt.Sprintf("none (locked-region hits %d, read %d MiB)", r.locked, r.readMiB)
	}
	var parts []string
	for _, l := range slices.Sorted(maps.Keys(r.byLabel)) {
		parts = append(parts, fmt.Sprintf("%s×%d", l, r.byLabel[l]))
	}
	return fmt.Sprintf("%s (locked-region hits %d, read %d MiB)", strings.Join(parts, " "), r.locked, r.readMiB)
}

// residueCount adds one region's hits to res, classifying each by whether the
// page it falls on is locked — the buffers' pages are — and returns how many
// times the victim's heap canary was found outside locked pages. lockedAt
// reports whether the byte at that offset of the region is locked; a scan
// whose OS answers per mapping passes a function that ignores the offset.
func residueCount(img []byte, windows []residueWindow, canary []byte, lockedAt func(off int) bool, res *residueScan) int {
	canaryHits := 0
	for off := 0; ; {
		i := bytes.Index(img[off:], canary)
		if i < 0 {
			break
		}
		if !lockedAt(off + i) {
			canaryHits++
		}
		off += i + 1
	}
	for _, w := range windows {
		for off := 0; ; {
			i := bytes.Index(img[off:], w.w)
			if i < 0 {
				break
			}
			if lockedAt(off + i) {
				res.locked++
			} else {
				res.byLabel[w.label]++
			}
			off += i + 1
		}
	}
	return canaryHits
}

// residueScanned is the common tail of a scan: a scan that read nothing, or
// found no canary, is broken, and its silence would prove nothing. Permission
// is decided when the victim's memory is opened, so this is never an
// environment to skip.
func residueScanned(t *testing.T, res residueScan, canaryHits int) residueScan {
	t.Helper()
	if canaryHits == 0 {
		t.Fatalf("the victim's live heap canary was not found in %d MiB of unlocked memory: the scan is broken, so its silence would prove nothing", res.readMiB)
	}
	return res
}
