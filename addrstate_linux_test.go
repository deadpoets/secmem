//go:build linux

package secmem

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// addrState reports whether addr lies in a mapping of this process, and
// whether a read of it would succeed, from /proc/self/maps.
func addrState(t *testing.T, addr uintptr) (mapped, accessible bool) {
	t.Helper()
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatalf("open /proc/self/maps: %v", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		l, err1 := strconv.ParseUint(lo, 16, 64)
		h, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if uint64(addr) >= l && uint64(addr) < h {
			return true, strings.HasPrefix(fields[1], "r")
		}
	}
	return false, false
}
