//go:build windows && (amd64 || arm64) && !race

// The Windows half of the residue proof: every thread of the victim is
// suspended to freeze it, VirtualQueryEx enumerates its address space,
// ReadProcessMemory reads it, and QueryWorkingSetEx answers, per page,
// whether the kernel has it locked in physical memory — the Windows
// counterpart of smaps' Locked field, and the same question asked of the
// kernel rather than of the victim. See residue_test.go.
//
// There is no memfd_secret here: a locked page is readable by a process with
// PROCESS_VM_READ, so the buffers' own pages are found and counted as
// locked hits. That is the platform's ceiling, stated in PROTECTION.md, and
// not something this test can measure away.

package secmemcrypto

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	win "golang.org/x/sys/windows"

	"github.com/deadpoets/secmem"
)

var (
	residueKernel32       = win.NewLazySystemDLL("kernel32.dll")
	residueProcSuspendThr = residueKernel32.NewProc("SuspendThread")
	residueProcQueryWSEx  = win.NewLazySystemDLL("psapi.dll").NewProc("QueryWorkingSetEx")
)

// residueFrozen holds the suspended thread handles of each frozen victim, so
// residueThaw can resume exactly what residueFreeze stopped. Scenarios run in
// parallel, each with its own victim.
var residueFrozen = struct {
	mu sync.Mutex
	m  map[int][]win.Handle
}{m: map[int][]win.Handle{}}

// residueSuspendThread is SuspendThread, which x/sys/windows declares no
// wrapper for (it has ResumeThread). It returns the thread's previous
// suspend count, or -1 on failure.
func residueSuspendThread(h win.Handle) error {
	r, _, err := residueProcSuspendThr.Call(uintptr(h))
	if int32(r) == -1 {
		return err
	}
	return nil
}

// residueThreadIDs lists the victim's threads. A snapshot is a moment's
// truth, which is why residueFreeze re-takes it until a pass suspends
// nothing new.
func residueThreadIDs(pid int) ([]uint32, error) {
	snap, err := win.CreateToolhelp32Snapshot(win.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer win.CloseHandle(snap)
	var ids []uint32
	var e win.ThreadEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = win.Thread32First(snap, &e); err == nil; err = win.Thread32Next(snap, &e) {
		if e.OwnerProcessID == uint32(pid) {
			ids = append(ids, e.ThreadID)
		}
	}
	return ids, nil
}

// residueFreeze suspends every thread of the victim, so no goroutine (the
// collector's included) moves memory under the scan. A suspended thread
// cannot start another, so a pass that finds nothing new has stopped the
// whole process.
func residueFreeze(t *testing.T, pid int) {
	t.Helper()
	var handles []win.Handle
	seen := map[uint32]bool{}
	for pass := 0; pass < 16; pass++ {
		ids, err := residueThreadIDs(pid)
		if err != nil {
			t.Fatalf("thread snapshot for victim %d: %v", pid, err)
		}
		fresh := 0
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			h, err := win.OpenThread(win.THREAD_SUSPEND_RESUME, false, id)
			if err != nil {
				continue // exited between the snapshot and here
			}
			if err := residueSuspendThread(h); err != nil {
				_ = win.CloseHandle(h)
				continue
			}
			handles = append(handles, h)
			fresh++
		}
		if fresh == 0 {
			break
		}
	}
	if len(handles) == 0 {
		t.Fatalf("no thread of victim %d could be suspended, so it is not frozen and the scan would race the collector", pid)
	}
	residueFrozen.mu.Lock()
	defer residueFrozen.mu.Unlock()
	residueFrozen.m[pid] = append(residueFrozen.m[pid], handles...)
}

// residueThaw lets the victim run again. It is safe to call when the victim
// is not frozen, which is what the cleanup path does.
func residueThaw(pid int) {
	residueFrozen.mu.Lock()
	handles := residueFrozen.m[pid]
	delete(residueFrozen.m, pid)
	residueFrozen.mu.Unlock()
	for _, h := range handles {
		_, _ = win.ResumeThread(h)
		_ = win.CloseHandle(h)
	}
}

// residueReadableProtect reports whether a committed region can be read.
// PAGE_GUARD pages raise an exception on access and PAGE_NOACCESS refuses;
// the guard pages around every SecureBuffer are exactly those.
func residueReadableProtect(protect uint32) bool {
	if protect&win.PAGE_GUARD != 0 || protect&win.PAGE_NOACCESS != 0 {
		return false
	}
	switch protect &^ (win.PAGE_NOCACHE | win.PAGE_WRITECOMBINE) {
	case win.PAGE_READONLY, win.PAGE_READWRITE, win.PAGE_WRITECOPY,
		win.PAGE_EXECUTE_READ, win.PAGE_EXECUTE_READWRITE, win.PAGE_EXECUTE_WRITECOPY:
		return true
	}
	return false
}

// residueWSEntry mirrors PSAPI_WORKING_SET_EX_INFORMATION: a page address and
// the flags the kernel reports for it. It is declared here rather than using
// x/sys/windows' own type because that type's address field is a Pointer,
// which a remote process's address is not, and because its single-bit
// accessors above bit 0 cannot work as written: Shared, Locked, LargePage and
// Bad each test `b&(1<<n) == 1`, which a bit at n > 0 can never equal, so all
// four always report false. Only Valid (bit 0) and the multi-bit fields
// (ShareCount, Win32Protection, Node), which mask and shift, are usable. Read
// the bits directly, as below, until that is fixed upstream.
type residueWSEntry struct {
	addr  uintptr
	attrs uint64
}

const (
	residueWSValid  = 1 << 0
	residueWSLocked = 1 << 22
)

// residueLockedPages asks the kernel which pages of a region are locked in
// physical memory, and returns its raw answer for each beside the verdict. A
// page that is not valid (not resident) cannot be locked. An error means the
// kernel was not asked or did not answer, which is a broken scan, not a
// region of unlocked pages: the caller must not count it as either.
//
// The entries go to the kernel through LazyProc.Call, which is
// //go:uintptrescapes: the conversion in its argument list moves them to the
// heap and keeps them alive across the call. x/sys/windows.QueryWorkingSetEx
// takes a plain uintptr and promises neither. The entries of a one- or
// two-page query do not escape and fit the compiler's stack buffer for small
// variable-sized makes, so with that wrapper they sat on this goroutine's
// stack, and a stack move between the conversion and the system call sent
// the kernel's answer to the old stack while this code read zeros (not
// valid, so "not locked", with a nil error) from the new one. A buffer's
// page is exactly such a one-page region.
// TestResidueLockedPages_SurvivesStackMove forces that move.
func residueLockedPages(proc win.Handle, base uintptr, size, pageSize int) (locked []bool, attrs []uint64, err error) {
	n := (size + pageSize - 1) / pageSize
	entries := make([]residueWSEntry, n)
	for i := range entries {
		entries[i].addr = base + uintptr(i*pageSize)
	}
	cb := uintptr(n) * unsafe.Sizeof(entries[0])
	r, _, callErr := residueProcQueryWSEx.Call(uintptr(proc), uintptr(unsafe.Pointer(&entries[0])), cb)
	if r == 0 {
		return nil, nil, callErr
	}
	locked = make([]bool, n)
	attrs = make([]uint64, n)
	for i := range entries {
		attrs[i] = entries[i].attrs
		locked[i] = entries[i].attrs&residueWSValid != 0 && entries[i].attrs&residueWSLocked != 0
	}
	return locked, attrs, nil
}

// scanResidue freezes the victim, reads every committed readable region of
// its address space, and counts pattern windows, splitting hits between the
// pages the kernel reports locked — where the buffers live — and the rest.
func scanResidue(t *testing.T, pid int, pats []residuePattern) residueScan {
	t.Helper()
	windows, err := residueWindows(pats)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := win.OpenProcess(win.PROCESS_QUERY_INFORMATION|win.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		residueEnvironmental(t, "cannot open the victim %d for reading (%v)", pid, err)
	}
	defer func() { _ = win.CloseHandle(proc) }()

	residueFreeze(t, pid)
	defer residueThaw(pid)

	canary := residueCanary()
	res := residueScan{byLabel: map[string]int{}}
	canaryHits := 0
	pageSize := os.Getpagesize()
	var read int64
	var img []byte
	for addr := uintptr(0); ; {
		var mbi win.MemoryBasicInformation
		if err := win.VirtualQueryEx(proc, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break // past the end of the user address space
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
		if mbi.State != win.MEM_COMMIT || !residueReadableProtect(mbi.Protect) || mbi.RegionSize > 64<<30 {
			continue
		}
		size := int(mbi.RegionSize)
		if cap(img) < size {
			img = make([]byte, size)
		}
		img = img[:size]
		clear(img)
		got := 0
		for pos := 0; pos < size; {
			want := min(1<<20, size-pos)
			var n uintptr
			err := win.ReadProcessMemory(proc, mbi.BaseAddress+uintptr(pos), &img[pos], uintptr(want), &n)
			if n > 0 {
				got += int(n)
				pos += int(n)
			}
			if err != nil {
				pos = (pos/pageSize + 1) * pageSize // skip the page that refused; it stays zero
			} else if n == 0 {
				break
			}
		}
		if got == 0 {
			continue
		}
		read += int64(got)
		locked, attrs, err := residueLockedPages(proc, mbi.BaseAddress, size, pageSize)
		if err != nil {
			// Neither an environment to skip nor a finding to count: the
			// region has been read, and nothing says which of its pages are
			// locked, so every hit in it would be a guess.
			t.Fatalf("%s: QueryWorkingSetEx for the victim's region %#x+%#x (protect %#x, type %#x): %v: the scan cannot classify what it read there, so it proves nothing",
				t.Name(), mbi.BaseAddress, size, mbi.Protect, mbi.Type, err)
		}
		canaryHits += residueCount(img, windows, canary, func(off int) bool {
			return locked[off/pageSize]
		}, func(off int) string {
			i := off / pageSize
			return fmt.Sprintf("%#x in region %#x+%#x (protect %#x, type %#x); the kernel says attrs=%#x valid=%v locked=%v",
				mbi.BaseAddress+uintptr(off), mbi.BaseAddress, size, mbi.Protect, mbi.Type,
				attrs[i], attrs[i]&residueWSValid != 0, attrs[i]&residueWSLocked != 0)
		}, &res)
	}
	res.readMiB = int(read >> 20)
	return residueScanned(t, res, canaryHits)
}

// TestResidueLockedPages_Detected pins the mechanism the scan uses to tell a
// buffer's memory from the rest of the process: a page of a SecureBuffer must
// be reported locked and an ordinary heap page must not. Without this the
// scan could call every page unlocked — counting the buffers themselves as
// residue — or every page locked, which would hide every leak it exists to
// find. Not a scenario: it needs no victim, and it asserts about this
// process.
func TestResidueLockedPages_Detected(t *testing.T) {
	buf, err := secmem.NewBuffer([]byte("a page of secret bytes for the locked-page control"))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	var bufPage uintptr
	if err := buf.WithBytesErr(func(b []byte) error {
		bufPage = uintptr(unsafe.Pointer(&b[0])) //nolint:secmem-lint // the address is not the secret
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	heap := make([]byte, os.Getpagesize())
	heap[0] = 1
	heapPage := uintptr(unsafe.Pointer(&heap[0]))

	proc := win.CurrentProcess()
	pageSize := os.Getpagesize()
	locked, attrs, err := residueLockedPages(proc, bufPage&^uintptr(pageSize-1), pageSize, pageSize)
	if err != nil {
		t.Fatalf("QueryWorkingSetEx: %v", err)
	}
	if !locked[0] {
		t.Errorf("a SecureBuffer's page is not reported locked (attrs=%#x): the scan cannot tell the buffers from the heap, and would count them as residue", attrs[0])
	}
	locked, attrs, err = residueLockedPages(proc, heapPage&^uintptr(pageSize-1), pageSize, pageSize)
	if err != nil {
		t.Fatalf("QueryWorkingSetEx: %v", err)
	}
	if locked[0] {
		t.Errorf("an ordinary heap page is reported locked (attrs=%#x): the scan would hide residue in unprotected memory", attrs[0])
	}
	runtime.KeepAlive(heap)
}

const residueStackMoveEnv = "SECMEMCRYPTO_RESIDUE_STACKMOVE_DEPTH"

// TestResidueLockedPages_SurvivesStackMove is the regression test for the
// lost answer residueLockedPages' comment describes. Each child process asks
// about one locked page, as its first QueryWorkingSetEx (the lazy procedure
// lookup then still has its slow path ahead of it, which is what grows the
// stack) from a fresh goroutine at a given stack depth. Some depth leaves
// too little stack for that path, the stack moves under the call, and a query
// whose entries are on it reports the locked page unlocked: 8 of these 61
// depths did, on go1.26 and go1.27, before the entries were made to escape.
// One process per depth, because only a process's first call takes the path.
func TestResidueLockedPages_SurvivesStackMove(t *testing.T) {
	if d := os.Getenv(residueStackMoveEnv); d != "" {
		residueStackMoveChild(d)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth <= 60; depth++ {
		cmd := exec.Command(exe, "-test.run=^TestResidueLockedPages_SurvivesStackMove$", "-test.count=1")
		cmd.Env = append(os.Environ(), residueStackMoveEnv+"="+strconv.Itoa(depth))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("depth %d: %v\n%s", depth, err, out)
		}
		switch {
		case strings.Contains(string(out), "STACKMOVE skip"):
			t.Skipf("depth %d: %s", depth, out)
		case strings.Contains(string(out), "STACKMOVE locked=true"):
		default:
			t.Errorf("depth %d: a locked page was not reported locked: the kernel's answer was lost\n%s", depth, out)
		}
	}
}

func residueStackMoveChild(depth string) {
	d, err := strconv.Atoi(depth)
	if err != nil {
		fmt.Printf("STACKMOVE error: %v\n", err)
		return
	}
	buf, err := secmem.NewBuffer([]byte("a page of secret bytes for the locked-page control"))
	if err != nil {
		fmt.Printf("STACKMOVE skip: NewBuffer: %v\n", err)
		return
	}
	defer func() { _ = buf.Destroy() }()
	var bufPage uintptr
	pageSize := os.Getpagesize()
	if err := buf.WithBytesErr(func(b []byte) error {
		bufPage = uintptr(unsafe.Pointer(&b[0])) &^ uintptr(pageSize-1) //nolint:secmem-lint // the address is not the secret
		return nil
	}); err != nil {
		fmt.Printf("STACKMOVE error: %v\n", err)
		return
	}
	done := make(chan string)
	go func() {
		var res string
		residueAtDepth(d, func() {
			locked, attrs, err := residueLockedPages(win.CurrentProcess(), bufPage, pageSize, pageSize)
			if err != nil {
				res = fmt.Sprintf("error: %v", err)
				return
			}
			res = fmt.Sprintf("locked=%v attrs=%#x", locked[0], attrs[0])
		})
		done <- res
	}()
	fmt.Printf("STACKMOVE %s\n", <-done)
}

// residueAtDepth calls fn with n of its own frames below it on the stack.
//
//go:noinline
func residueAtDepth(n int, fn func()) byte {
	var pad [96]byte
	pad[n%96] = byte(n)
	if n == 0 {
		fn()
		return pad[0]
	}
	return residueAtDepth(n-1, fn) + pad[n%96]
}

// residueVictimGODEBUG turns Go's asynchronous preemption off in the victim,
// except for the scenarios that exist to measure what a preemption leaves
// behind.
//
// Scrub cannot block preemption here — there is no signal to mask — and the
// runtime does not keep the whole saved register file on the preempted
// goroutine's stack, which a window would burn. In go1.26 and go1.27,
// asyncPreempt writes the vector registers to p.xRegs.scratch, at a 64-byte
// stride, and the runtime then copies that into an xRegState block allocated
// off-heap from a fixalloc (runtime/preempt_xreg.go). Neither is cleared once
// the state has been restored: the scratch lives in the P, which never dies,
// and the block is NotInHeap, so even a runtime/secret build does not erase
// it — its erasure is of heap objects the collector finds unreachable. A
// preemption that lands while a key is in two vector registers therefore
// leaves two copies of it per P that ran the goroutine, until the next
// preemption on that P overwrites them.
//
// Left on, that makes every scenario a coin flip. X25519Key's SharedSecret —
// microseconds of work — was caught by it about once in a hundred runs of
// that scenario under load here, and once in CI, with the copies at
// asyncPreempt's 64-byte stride in two regions outside every stack. A scan
// that fails that way is reporting the platform, not this module, so the
// platform is measured on its own: the scenarios that exist to observe a
// preemption keep it on — the two control/preempted-copy controls, which
// assert the copies appear, and WithBytesErr/copy-then-preempted, which is
// the proof that the borrow paths clear the registers and would prove nothing
// without one. Those three keep the residual risk this comment describes;
// everything else no longer has it. PROTECTION.md states the limit for
// callers, whose mitigation is this same GODEBUG.
func residueVictimGODEBUG(sc residueScenario) string {
	if sc.needsPreemption {
		return ""
	}
	return "asyncpreemptoff=1"
}
