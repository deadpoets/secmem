//go:build linux

// Proof tests for the per-mapping kernel advice. Instead of trusting that
// madvise returned 0 — or that Capabilities repeated what the syscall said —
// these read the kernel's own record of the VMA flags from /proc/self/smaps
// and require the flag behind each claim on the secret area, on BOTH
// allocation tiers (the anon+mlock path and, where live, memfd_secret):
//
//	lo  VM_LOCKED     mlock, or secretmem's own lock       — "no swap"
//	dd  VM_DONTDUMP   MADV_DONTDUMP, or secretmem's own    — "excluded from dumps"
//	dc  VM_DONTCOPY   MADV_DONTFORK                        — "not inherited across fork"
//	nh  VM_NOHUGEPAGE MADV_NOHUGEPAGE                      — "no THP copies"
//	mg  VM_MERGEABLE  must be ABSENT after MADV_UNMERGEABLE — "no KSM copies"
//
// The rule for a missing flag: when Capabilities claims the protection, a
// missing flag is a failure — the report and the kernel disagree. When it
// does not claim it, the test re-issues the same advice to obtain the
// kernel's refusal and skips with that reason; if the kernel accepts the
// re-issued advice, the allocator's own call was dropped, which is a failure
// too. Every skip is a visible subtest, audited in CI.

package secmem

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// smapsLineFor returns the line beginning with field (e.g. "VmFlags:" or
// "Rss:") of the /proc/self/smaps entry whose range starts at addr, or an
// error if the mapping or the field is not found.
func smapsLineFor(addr uintptr, field string) (string, error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	prefix := fmt.Sprintf("%x-", addr)
	inTarget := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "-") {
			inTarget = strings.HasPrefix(line, prefix)
		}
		if inTarget && strings.HasPrefix(line, field) {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("mapping at %x (field %q) not found in smaps", addr, field)
}

// vmFlagsFor returns the VmFlags line of the /proc/self/smaps entry whose
// range starts at addr.
func vmFlagsFor(addr uintptr) (string, error) {
	return smapsLineFor(addr, "VmFlags:")
}

// hasVMFlag reports whether the two-letter flag is among the VmFlags tokens.
// Token match, not substring: "lo" must not be found inside another flag.
func hasVMFlag(vmFlags, flag string) bool {
	for _, tok := range strings.Fields(strings.TrimPrefix(vmFlags, "VmFlags:")) {
		if tok == flag {
			return true
		}
	}
	return false
}

// secretAreaAddr is the start of the buffer's secret VMA.
func secretAreaAddr(buf *SecureBuffer) uintptr {
	return uintptr(unsafe.Pointer(&buf.region.inner[0]))
}

// requireVMFlag is the per-flag assertion. claimed is what Capabilities
// reports for the protection (false when it has no field for it); advice is
// the madvise that sets the flag, re-issued only to learn the kernel's reason
// when the flag is absent and nothing claimed it.
func requireVMFlag(t *testing.T, buf *SecureBuffer, flag, what string, claimed bool, advice int) {
	t.Helper()
	flags, err := vmFlagsFor(secretAreaAddr(buf))
	if err != nil {
		t.Fatalf("reading smaps: %v", err)
	}
	if hasVMFlag(flags, flag) {
		t.Logf("%s in force: kernel records %q", what, flag)
		return
	}
	if claimed {
		t.Fatalf("Capabilities reports %s in force but the kernel's VmFlags lack %q: %s", what, flag, flags)
	}
	// Not claimed and not recorded. Ask the kernel why, on the same mapping.
	if err := unix.Madvise(buf.region.inner, advice); err != nil {
		t.Skipf("kernel refuses %s on this mapping (%v); Capabilities agrees it is not in force", what, err)
	}
	after, err := vmFlagsFor(secretAreaAddr(buf))
	if err != nil {
		t.Fatalf("re-reading smaps: %v", err)
	}
	if hasVMFlag(after, flag) {
		t.Fatalf("%s: the advice succeeds when re-issued, so the allocator's own call was dropped or never made (VmFlags before: %s)", what, flags)
	}
	t.Fatalf("%s: madvise returned success but the kernel recorded no %q flag: %s", what, flag, after)
}

// thpPresent reports whether the kernel was built with transparent hugepages;
// without them MADV_NOHUGEPAGE is unnecessary and the flag is never recorded.
func thpPresent() bool {
	_, err := os.Stat("/sys/kernel/mm/transparent_hugepage")
	return err == nil
}

// runVMFlagProofs asserts the lock, dump, fork and THP flags on buf.
func runVMFlagProofs(t *testing.T, buf *SecureBuffer) {
	t.Helper()
	caps := buf.Capabilities()
	t.Logf("tier: memfd_secret=%v; %s", caps.MemfdSecret, caps)

	t.Run("lo_locked", func(t *testing.T) {
		requireVMFlag(t, buf, "lo", "page locking (mlock)", caps.Mlocked, unix.MADV_NORMAL)
	})
	t.Run("dd_dontdump", func(t *testing.T) {
		requireVMFlag(t, buf, "dd", "core-dump exclusion (MADV_DONTDUMP)", caps.NoDump, unix.MADV_DONTDUMP)
	})
	t.Run("dc_dontfork", func(t *testing.T) {
		requireVMFlag(t, buf, "dc", "fork exclusion (MADV_DONTFORK)", caps.NoFork, unix.MADV_DONTFORK)
	})
	t.Run("nh_nohugepage", func(t *testing.T) {
		if !thpPresent() {
			t.Skip("kernel built without THP — the opt-out is unnecessary and unrecorded")
		}
		requireVMFlag(t, buf, "nh", "THP opt-out (MADV_NOHUGEPAGE)", false, unix.MADV_NOHUGEPAGE)
	})
}

// TestMadvise_AnonTierFlagsInForce proves the flags on the mmap+mlock tier,
// which NewSyscallSafeBuffer always uses (never memfd).
func TestMadvise_AnonTierFlagsInForce(t *testing.T) {
	buf, err := NewSyscallSafeBuffer([]byte("no-thp-copies-of-me"))
	if err != nil {
		t.Skipf("NewSyscallSafeBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = buf.Destroy() }()
	if buf.Capabilities().MemfdSecret {
		t.Fatal("NewSyscallSafeBuffer produced a memfd_secret-backed buffer; this test is the anon tier's proof")
	}
	runVMFlagProofs(t, buf)
}

// TestMadvise_MemfdSecretTierFlagsInForce proves the same flags on the
// memfd_secret tier. secretmem sets VM_LOCKED and VM_DONTDUMP itself at mmap;
// MADV_DONTFORK and MADV_NOHUGEPAGE are the allocator's own calls on that VMA.
func TestMadvise_MemfdSecretTierFlagsInForce(t *testing.T) {
	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = buf.Destroy() }()
	if !buf.Capabilities().MemfdSecret {
		t.Skip("memfd_secret not in force on this kernel — the anon-tier test covers this allocation")
	}
	runVMFlagProofs(t, buf)
	// KSM never touches a MAP_SHARED mapping, so the merge flag cannot be set
	// here and nothing needs to clear it; recorded so the tier's posture is
	// visible in the log, not asserted as a proof of an advice.
	flags, err := vmFlagsFor(secretAreaAddr(buf))
	if err != nil {
		t.Fatal(err)
	}
	if hasVMFlag(flags, "mg") {
		t.Errorf("memfd_secret mapping is marked mergeable: %s", flags)
	}
}

// ksmMergeAnyChildEnv marks the re-exec'd child of the KSM proof.
const ksmMergeAnyChildEnv = "SECMEM_KSM_MERGE_ANY_CHILD"

// TestMadvise_UnmergeableInForce proves the KSM opt-out with the kernel's
// own record. MADV_UNMERGEABLE only clears VM_MERGEABLE, and a fresh private
// mapping never carries it — so on an ordinary process the flag's absence
// proves nothing. The threat the advice exists for is PR_SET_MEMORY_MERGE
// (Linux 6.4+): a process opted into KSM as a whole, where every new
// compatible mapping is marked mergeable at creation. The child does exactly
// that, confirms with a plain anonymous control mapping that the kernel now
// records "mg", and then requires the secret area to lack it.
//
// Runs in a child because the prctl is process-wide. It needs
// CAP_SYS_RESOURCE, so on an unprivileged runner the child skips with EPERM
// and the root lane in CI is where the proof runs.
func TestMadvise_UnmergeableInForce(t *testing.T) {
	if os.Getenv(ksmMergeAnyChildEnv) == "1" {
		ksmMergeAnyChild(t)
		return
	}
	if _, err := os.Stat("/sys/kernel/mm/ksm"); err != nil {
		t.Skip("kernel built without KSM — MADV_UNMERGEABLE has nothing to record")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMadvise_UnmergeableInForce$", "-test.v")
	cmd.Env = append(os.Environ(), ksmMergeAnyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if reason, skipped := childSkipReason(out); skipped {
		t.Skipf("child skipped: %s", reason)
	}
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
}

func ksmMergeAnyChild(t *testing.T) {
	if err := unix.Prctl(unix.PR_SET_MEMORY_MERGE, 1, 0, 0, 0); err != nil {
		switch {
		case errors.Is(err, unix.EPERM):
			t.Skipf("PR_SET_MEMORY_MERGE refused (%v): needs CAP_SYS_RESOURCE; the root lane runs this proof", err)
		case errors.Is(err, unix.EINVAL):
			t.Skipf("PR_SET_MEMORY_MERGE unsupported (%v): needs Linux 6.4+ with CONFIG_KSM", err)
		default:
			t.Fatalf("PR_SET_MEMORY_MERGE: %v", err)
		}
	}
	page := os.Getpagesize()

	// Control: a private anonymous mapping made now must be marked mergeable,
	// or the flag is unobservable and the subject's clean record is vacuous.
	ctrl, err := unix.Mmap(-1, 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("control mmap: %v", err)
	}
	defer func() { _ = unix.Munmap(ctrl) }()
	ctrlFlags, err := vmFlagsFor(uintptr(unsafe.Pointer(&ctrl[0])))
	if err != nil {
		t.Fatal(err)
	}
	if !hasVMFlag(ctrlFlags, "mg") {
		t.Fatalf("control: a fresh private anonymous mapping is not marked mergeable under PR_SET_MEMORY_MERGE (%s), so the absence of the flag on the secret area would prove nothing", ctrlFlags)
	}

	// Subject: the anon tier's secret area, which the allocator advised
	// MADV_UNMERGEABLE after the same process-wide opt-in marked it.
	buf, err := NewSyscallSafeBuffer([]byte("never-deduplicated"))
	if err != nil {
		t.Skipf("NewSyscallSafeBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = buf.Destroy() }()
	flags, err := vmFlagsFor(secretAreaAddr(buf))
	if err != nil {
		t.Fatal(err)
	}
	if hasVMFlag(flags, "mg") {
		t.Fatalf("MADV_UNMERGEABLE not in force: the secret area is still marked mergeable under PR_SET_MEMORY_MERGE: %s", flags)
	}
	// The guard reservation the area was split from was never advised, so it
	// still carries the mark — which shows the clear came from the advice on
	// the secret area, not from the mapping's construction.
	if guard, err := vmFlagsFor(uintptr(unsafe.Pointer(&buf.region.outer[0]))); err == nil {
		t.Logf("guard reservation (not advised): %s", guard)
	}
	t.Logf("secret area under PR_SET_MEMORY_MERGE: %s", flags)
}
