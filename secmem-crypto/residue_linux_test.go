//go:build linux && (amd64 || arm64) && !race

// The Linux half of the residue proof: SIGSTOP to freeze the victim (Yama's
// ptrace_scope=1 permits its parent), /proc/<pid>/smaps to enumerate its
// mappings and learn which the kernel reports as locked, and
// /proc/<pid>/mem to read them — tolerating the pages memfd_secret refuses,
// which is the point of memfd_secret. See residue_test.go.

package secmemcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

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

// residueFreeze stops the victim and waits until the kernel reports it
// stopped, so no goroutine (the collector's included) moves memory under the
// scan.
func residueFreeze(t *testing.T, pid int) {
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
	residueFreeze(t, pid)
	defer residueThaw(pid)

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
		locked := m.locked
		canaryHits += residueCount(img, windows, canary, func(int) bool { return locked }, &res)
	}
	res.readMiB = int(read >> 20)
	return residueScanned(t, res, canaryHits)
}

// residueThaw lets the victim run again.
func residueThaw(pid int) {
	_ = syscall.Kill(pid, syscall.SIGCONT)
}
