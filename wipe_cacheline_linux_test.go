//go:build linux && (amd64 || arm64)

// Platform-assumption guard for the cache-flush stride.
//
// Both assembly wipes walk the region in fixed 64-byte steps — arm64 issues
// `DC CIVAC` at ptr&^63 + 64n (wipe_arm64.s), amd64 issues CLFLUSH/CLFLUSHOPT
// on the same lattice (wipe_amd64.s) — because 64 bytes is the cache line on
// every core secmem has been run on. That constant is an assumption about the
// hardware, and it is only safe in ONE direction:
//
//   - line size > 64: each line is flushed more than once. Wasteful, correct.
//   - line size == 64: exact.
//   - line size < 64: the loop STEPS OVER whole lines. A 32-byte-line core
//     would leave every second line unflushed, so secret bytes could survive
//     in cache after a wipe the library reported as complete.
//
// Nothing in the wipe detects that; it would be silent. This test asks the
// kernel for the real geometry and fails if the assumption is violated, so the
// first machine where it is wrong reports a test failure rather than a quiet
// downgrade of the wipe guarantee.
//
// Measured 64 on every level of every box the suite has run on: Cortex-A78AE
// (Tegra 234), Cortex-A53 (RK3328), and x86_64. See KERNELS.md.

package secmem

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// wipeFlushStride mirrors the 64-byte step hardcoded in wipe_amd64.s and
// wipe_arm64.s.
const wipeFlushStride = 64

// TestWipe_CacheLineNotSmallerThanFlushStride verifies that no data or unified
// cache on this machine has a line shorter than the wipe's flush stride.
//
// Instruction caches are excluded deliberately: the flush loops are data-cache
// maintenance (DC CIVAC to the Point of Coherency; CLFLUSH), so an I-cache
// geometry that differs cannot cause a secret byte to be missed.
func TestWipe_CacheLineNotSmallerThanFlushStride(t *testing.T) {
	const cpuCache = "/sys/devices/system/cpu/cpu0/cache"
	entries, err := filepath.Glob(cpuCache + "/index*")
	if err != nil || len(entries) == 0 {
		t.Skipf("no cache geometry exposed at %s — cannot verify the flush stride here", cpuCache)
	}

	checked := 0
	for _, dir := range entries {
		kind, err := readTrimmed(filepath.Join(dir, "type"))
		if err != nil {
			continue
		}
		// "Data" and "Unified" hold secret bytes; "Instruction" does not.
		if kind != "Data" && kind != "Unified" {
			continue
		}
		raw, err := readTrimmed(filepath.Join(dir, "coherency_line_size"))
		if err != nil {
			continue
		}
		size, err := strconv.Atoi(raw)
		if err != nil || size <= 0 {
			continue
		}
		level, _ := readTrimmed(filepath.Join(dir, "level"))
		checked++

		if size < wipeFlushStride {
			t.Errorf("L%s %s cache line is %d bytes, smaller than the %d-byte flush stride: "+
				"the wipe's flush loop steps over %d of every %d bytes, so a wiped region can "+
				"retain secret bytes in cache. Fix the stride in wipe_amd64.s / wipe_arm64.s.",
				level, kind, size, wipeFlushStride, wipeFlushStride-size, wipeFlushStride)
		}
		t.Logf("L%s %s line=%d bytes (flush stride %d)", level, kind, size, wipeFlushStride)
	}

	if checked == 0 {
		t.Skip("no data or unified cache reported line sizes — nothing to verify")
	}
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
