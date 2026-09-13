//go:build linux && (amd64 || arm64) && !race

// Out-of-process key residue proof. For every entry point that holds or
// derives a secret, a victim subprocess receives known key material straight
// into a SecureBuffer, builds the object, uses it, and is frozen with SIGSTOP
// at each phase while this process — its parent, which Yama's ptrace_scope=1
// permits — reads every readable page of it through /proc/<pid>/mem and
// counts the key's encodings found outside locked mappings. The encodings
// are not just the raw key: they include what the implementation derives
// from it and would leak it just as well (see residue_scenarios_test.go).
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
// does not support; CI runs it in its own non-race job on amd64 and arm64,
// once per build mode.

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
	"syscall"
	"testing"
	"time"

	"github.com/deadpoets/secmem"
)

const (
	residueVictimEnv = "SECMEMCRYPTO_RESIDUE_VICTIM"
	residueAuxEnv    = "SECMEMCRYPTO_RESIDUE_AUX"

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
	t.Logf("runtimesecret=%v euid=%d", secmem.RuntimeSecretActive(), os.Geteuid())
	for _, sc := range residueScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			runResidueScenario(t, exe, sc)
		})
	}
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
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGCONT)
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
	if sc.class == residueContained {
		none("construction", r)
	}

	v.do('o')
	r = scanResidue(t, v.pid, pats)
	t.Logf("used:        %s", r)
	switch sc.class {
	case residueContained:
		none("use", r)
	case residueTransient:
		some("use", "this entry point is classified transient: every operation copies the key through the heap", r)
	case residueControlScrub, residueControlPlain:
		some("use", "the control copies the secret to the heap on every operation", r)
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
	case sc.class == residueContained:
		none("after GC", r)
	case sc.class == residueControlPlain:
		some("after GC", "a heap copy made outside Scrub is never erased by the runtime, on any build", r)
	case rs:
		// runtime/secret erases allocations made inside Scrub once the
		// collector finds them unreachable; that is the whole of its promise.
		none(fmt.Sprintf("after %d GC cycles on a runtimesecret build", residueSettleRounds), r)
	case sc.class == residueControlScrub:
		some("after GC", "a legacy build has no runtime erasure, so a dropped heap copy survives the collector", r)
	}

	v.do('d')
	r = scanResidue(t, v.pid, pats)
	t.Logf("destroyed:   %s", r)
	if r.locked > 0 {
		t.Errorf("%s: after Destroy the secret is still in locked memory: %s", sc.name, r)
	}
	if sc.class == residueContained {
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

type residueMapping struct {
	start, end uint64
	readable   bool
	locked     bool
	name       string
}

func readSmaps(pid int) ([]residueMapping, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/smaps", pid))
	if err != nil {
		return nil, err
	}
	var ms []residueMapping
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && len(f[1]) == 4 && strings.Contains(f[0], "-") {
			lo, hi, _ := strings.Cut(f[0], "-")
			start, e1 := strconv.ParseUint(lo, 16, 64)
			end, e2 := strconv.ParseUint(hi, 16, 64)
			if e1 == nil && e2 == nil && end > start {
				m := residueMapping{start: start, end: end, readable: f[1][0] == 'r'}
				if len(f) >= 6 {
					m.name = strings.Join(f[5:], " ")
				}
				ms = append(ms, m)
				continue
			}
		}
		if len(f) >= 2 && f[0] == "Locked:" && len(ms) > 0 && f[1] != "0" {
			ms[len(ms)-1].locked = true
		}
	}
	if len(ms) == 0 {
		return nil, errors.New("no mappings parsed")
	}
	return ms, nil
}

// freeze stops the victim and waits until the kernel reports it stopped, so
// no goroutine (the collector's included) moves memory under the scan.
func freeze(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP victim: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatalf("victim stat: %v", err)
		}
		if i := bytes.LastIndexByte(b, ')'); i > 0 && len(b) > i+2 && (b[i+2] == 'T' || b[i+2] == 't') {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("victim %d did not stop within 5s", pid)
}

// scanResidue freezes the victim, reads every readable mapping through
// /proc/<pid>/mem (tolerating unreadable pages, as memfd_secret's are), and
// counts pattern windows, splitting hits between locked mappings — where the
// buffers live — and everything else.
func scanResidue(t *testing.T, pid int, pats []residuePattern) residueScan {
	t.Helper()
	windows, err := residueWindows(pats)
	if err != nil {
		t.Fatal(err)
	}
	freeze(t, pid)
	defer func() { _ = syscall.Kill(pid, syscall.SIGCONT) }()

	memf, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		residueEnvironmental(t, "cannot open the victim's /proc/%d/mem (%v): ptrace is not permitted here", pid, err)
	}
	defer memf.Close()
	maps, err := readSmaps(pid)
	if err != nil {
		t.Fatalf("victim smaps: %v", err)
	}

	canary := residueCanary()
	res := residueScan{byLabel: map[string]int{}}
	canaryHits := 0
	page := os.Getpagesize()
	var read int64
	var img []byte
	for _, m := range maps {
		if !m.readable || m.name == "[vsyscall]" || m.end-m.start > 64<<30 {
			continue
		}
		size := int(m.end - m.start)
		if cap(img) < size {
			img = make([]byte, size)
		}
		img = img[:size]
		clear(img)
		got := 0
		for pos := 0; pos < size; {
			want := min(1<<20, size-pos)
			n, rerr := memf.ReadAt(img[pos:pos+want], int64(m.start)+int64(pos))
			if n > 0 {
				got += n
				pos += n
			}
			if rerr != nil {
				pos = (pos/page + 1) * page // skip the page that refused; it stays zero
			} else if n == 0 {
				break
			}
		}
		if got == 0 {
			continue
		}
		read += int64(got)
		if !m.locked {
			canaryHits += bytes.Count(img, canary)
		}
		for _, w := range windows {
			c := bytes.Count(img, w.w)
			if c == 0 {
				continue
			}
			if m.locked {
				res.locked += c
			} else {
				res.byLabel[w.label] += c
			}
		}
	}
	res.readMiB = int(read >> 20)
	// Permission is decided when /proc/<pid>/mem is opened (the kernel's
	// ptrace access check runs there), so a victim that opened but yielded
	// nothing, or no canary, is a broken scan — never an environment to skip.
	if canaryHits == 0 {
		t.Fatalf("the victim's live heap canary was not found in %d MiB of unlocked memory: the scan is broken, so its silence would prove nothing", res.readMiB)
	}
	return res
}
