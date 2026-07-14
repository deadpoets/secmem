//go:build linux

// Out-of-process extraction proof. The in-tree isolation test
// (memfd_isolation_linux_test.go) reads /proc/self/mem from *inside* the
// process that owns the secret; this one proves the stronger, real-world claim:
// a *separate* process cannot extract a SecureBuffer's contents. It launches a
// victim subprocess that holds one marker only inside a SecureBuffer
// (memfd_secret) and an identical-shaped control marker on the ordinary Go
// heap, then — as the victim's parent, which ptrace_scope=1 permits — scans the
// victim's entire readable address space with the two primitives a debugger or
// attacker actually uses: /proc/<pid>/mem and process_vm_readv(2).
//
// The control marker MUST be recoverable (the technique works); the secret
// marker MUST be recoverable by neither primitive. Both markers are computed at
// runtime and never written as literals, so neither sits in the binary's
// read-only data. The proof is scoped honestly: it asserts a failure only on a
// genuine leak, and skips (never fails) when the environment cannot host it —
// no memfd_secret backing, or ptrace not permitted.

package secmem

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const extractionVictimEnv = "SECMEM_EXTRACTION_VICTIM"

// extractionKeepAlive holds the victim's control marker. A package-level var
// forces it onto the heap and keeps it reachable for the process lifetime, so
// the marker is deterministically present in ordinary readable memory (a local
// slice can stay on the goroutine stack and evade the scan).
var extractionKeepAlive []byte

// Markers are derived, never literal, so they never appear in .rodata.
func extractionSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xA0 ^ byte(i*7+3)
	}
	return b
}

func extractionControl() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0x50 ^ byte(i*5+1)
	}
	return b
}

// TestExtractionVictimHelper is the victim subprocess. It is an immediate no-op
// during an ordinary test run and only assumes the victim role when the parent
// re-execs it with extractionVictimEnv set (the os/exec TestHelperProcess
// idiom). As the victim it writes the control marker to the heap, the secret
// marker into a SecureBuffer, announces "READY <pid> <memfd 0|1>", and blocks
// until the parent closes its stdin.
func TestExtractionVictimHelper(t *testing.T) {
	if os.Getenv(extractionVictimEnv) != "1" {
		return
	}

	extractionKeepAlive = extractionControl() // ordinary heap; an attacker SHOULD find this
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "victim: NewEmptyBuffer:", err)
		os.Exit(3)
	}
	// Fill the locked region in place; the secret never lands on the heap.
	if err := buf.WithBytes(func(p []byte) {
		for i := range p {
			p[i] = 0xA0 ^ byte(i*7+3)
		}
	}); err != nil {
		fmt.Fprintln(os.Stderr, "victim: WithBytes:", err)
		os.Exit(3)
	}
	memfd := 0
	if buf.Capabilities().MemfdSecret {
		memfd = 1
	}
	fmt.Printf("READY %d %d\n", os.Getpid(), memfd)
	_ = os.Stdout.Sync()

	var one [1]byte
	_, _ = os.Stdin.Read(one[:]) // block until the parent closes stdin
	_ = buf.Destroy()
	os.Exit(0)
}

// procVMReadvInto reads len(dst) bytes at remote address addr in process pid via
// process_vm_readv(2) — the syscall gdb/delve use. The remote address is carried
// as a plain uintptr in a RemoteIovec and interpreted by the kernel in the
// target process; nothing is dereferenced locally.
func procVMReadvInto(pid int, addr uint64, dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	local := []unix.Iovec{{Base: &dst[0]}}
	local[0].SetLen(len(dst))
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(dst)}}
	return unix.ProcessVMReadv(pid, local, remote, 0)
}

// TestExternalExtraction_SecureBufferUnreadable proves a separate process cannot
// read a SecureBuffer's bytes, using both /proc/<pid>/mem and process_vm_readv.
func TestExternalExtraction_SecureBufferUnreadable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestExtractionVictimHelper$")
	cmd.Env = append(os.Environ(), extractionVictimEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start victim: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()

	// Read the victim's READY line (skip any test-framework chatter).
	br := bufio.NewReader(stdout)
	var pid, memfd int
	ready := false
	for {
		line, rerr := br.ReadString('\n')
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "READY ") {
			if _, err := fmt.Sscanf(s, "READY %d %d", &pid, &memfd); err != nil {
				t.Fatalf("parse %q: %v", s, err)
			}
			ready = true
			break
		}
		if rerr != nil {
			break
		}
	}
	if !ready {
		t.Fatal("victim did not report READY")
	}
	if memfd != 1 {
		t.Skip("victim's SecureBuffer is not memfd_secret-backed on this kernel — ordinary locked memory is readable by design, so there is nothing to prove")
	}

	memf, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		t.Skipf("cannot open the victim's /proc/%d/mem (%v) — ptrace is not permitted in this environment", pid, err)
	}
	defer func() { _ = memf.Close() }()

	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("read victim maps: %v", err)
	}

	secret := extractionSecret()
	control := extractionControl()
	pageSize := os.Getpagesize()

	// readRegion copies [start,end) out of the victim, tolerating holes
	// (unpopulated or unreadable pages) by zero-filling them and skipping to the
	// next page, so a marker sitting in a later page of a sparsely-populated heap
	// arena is still seen — an all-or-nothing read would drop the whole arena the
	// moment its first page is a hole. Returns the image and bytes actually read.
	readRegion := func(start, end uint64) ([]byte, int) {
		size := int(end - start)
		img := make([]byte, size)
		read := 0
		for pos := 0; pos < size; {
			want := 1 << 20
			if size-pos < want {
				want = size - pos
			}
			n, rerr := memf.ReadAt(img[pos:pos+want], int64(start)+int64(pos))
			if n > 0 {
				read += n
				pos += n
			}
			if rerr != nil {
				next := ((pos / pageSize) + 1) * pageSize // skip the faulting page
				if next <= pos {
					next = pos + pageSize
				}
				pos = next
			} else if n == 0 {
				break
			}
		}
		return img, read
	}

	var (
		controlHits, secretHits int
		scanned                 int64
		ctrlAddr                uint64
		ctrlLen                 int
		secretStart             uint64
		secretSize              int
		secretFound             bool
	)

	sc := bufio.NewScanner(bytes.NewReader(maps))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || len(f[1]) < 2 || f[1][0] != 'r' {
			continue
		}
		b := strings.SplitN(f[0], "-", 2)
		if len(b) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(b[0], 16, 64)
		end, err2 := strconv.ParseUint(b[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start || int(end-start) > (1<<30) {
			continue
		}
		img, read := readRegion(start, end)
		if read == 0 {
			// A writable-yet-entirely-unreadable mapping is the memfd_secret
			// hallmark: ordinary writable memory reads fine, and kernel special
			// regions such as [vvar] are read-only. Record the first such region.
			if f[1][1] == 'w' && !secretFound {
				secretStart, secretSize, secretFound = start, int(end-start), true
			}
			continue
		}
		scanned += int64(read)
		controlHits += bytes.Count(img, control)
		secretHits += bytes.Count(img, secret)
		if ctrlLen == 0 {
			if idx := bytes.Index(img, control); idx >= 0 {
				ctrlAddr, ctrlLen = start+uint64(idx), len(control)
			}
		}
	}

	// Environmental guards: skip (never fail) when the host can't host the proof.
	if scanned == 0 {
		t.Skip("no region of the victim was readable — ptrace is not permitted in this environment")
	}
	if controlHits == 0 {
		t.Skipf("control marker not found across %d MiB of readable memory — scan inconclusive on this host", scanned/(1<<20))
	}
	if !secretFound {
		t.Skip("could not locate the victim's memfd_secret region — nothing to assert")
	}

	// Primitive 1 — /proc/<pid>/mem: the secret must be absent everywhere.
	if secretHits != 0 {
		t.Fatalf("SecureBuffer secret recovered %d time(s) via /proc/%d/mem by an external process — isolation FAILED", secretHits, pid)
	}

	// Primitive 2 — process_vm_readv(2): prove the primitive works by reading the
	// control marker at its known address, then prove it cannot read the secret.
	got := make([]byte, ctrlLen)
	if n, err := procVMReadvInto(pid, ctrlAddr, got); err != nil || n != ctrlLen || !bytes.Equal(got, control) {
		t.Logf("process_vm_readv could not read the control marker (n=%d err=%v) — /proc/mem already established the secret is absent; skipping its assertion", n, err)
	} else {
		leak := make([]byte, secretSize)
		m, verr := procVMReadvInto(pid, secretStart, leak)
		if verr == nil && m > 0 && bytes.Contains(leak[:m], secret) {
			t.Fatalf("process_vm_readv recovered the SecureBuffer secret (%d bytes) — isolation FAILED", m)
		}
		t.Logf("process_vm_readv: control marker read OK, secret region unreadable (n=%d err=%v)", m, verr)
	}

	t.Logf("external process scanned %d MiB: control found %d time(s), secret found 0 — /secretmem unreadable via /proc/mem and process_vm_readv",
		scanned/(1<<20), controlHits)
}
