// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto. See
// doc.go for the list of changes; every departure from upstream is also
// marked "secmem:" inline.

package argon2

import (
	"encoding/binary"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/crypto/blake2b"

	"github.com/deadpoets/secmem"
)

// Version is the Argon2 version implemented by this package.
const Version = 0x13

// Mode selects the Argon2 variant. The values are the RFC 9106 type codes
// and are hashed into H0, so they must not be renumbered.
type Mode uint32

const (
	ModeD  Mode = 0 // Argon2d: data-dependent addressing throughout.
	ModeI  Mode = 1 // Argon2i: data-independent addressing throughout.
	ModeID Mode = 2 // Argon2id: independent for the first half pass, dependent after.
)

const (
	blockLength = 128
	syncPoints  = 4
	h0Length    = blake2b.Size + 8
)

type block [blockLength]uint64

// zeroBlock is the constant all-zero block: the second input of the
// data-independent address generator and, on the SSE path, the operand
// that stands in for upstream's freshly zeroed stack temporary. It is only
// ever read; TestWorkspaceWipe asserts it stayed zero.
var zeroBlock block //nolint:gochecknoglobals // read-only constant, shared by all lanes

// laneScratch is the per-lane working state that upstream keeps as stack
// locals of each processSegment goroutine (addresses, in) plus blamka's
// temporary (tmp). secmem: hoisted here so the parent owns it — a worker
// goroutine's stack is reachable by nothing after it exits, and the runtime
// hands it to the next goroutine unwiped.
type laneScratch struct {
	addresses, in, tmp block
}

// initInputReserve is the room a Workspace keeps for the H0 input (params ‖
// len‖password ‖ len‖salt ‖ len‖K ‖ len‖X). Inputs that do not fit are
// hashed from a heap buffer allocated for the call and wiped after it; a
// 4 KiB reserve holds any realistic password plus pepper without that.
const initInputReserve = 4096

// Workspace holds every byte of working state one derivation touches, as
// views into one contiguous region the caller supplies ([Bind]) or that
// [NewWorkspace] allocates on the heap. Its zero value is not usable. A
// Workspace may be reused across derivations with the same memory and
// threads, and must be [Workspace.Wipe]d between them (and after the last
// one) — Derive does not wipe on the caller's behalf, so that a test can
// inspect the residue (and prove it absent) after the call.
type Workspace struct {
	requested uint32 // the memory parameter as given: it is what H0 commits to
	memory    uint32 // adjusted: a multiple of syncPoints*threads, ≥ 2*syncPoints*threads
	threads   uint32

	mem []byte // the whole region; Wipe zeroes it in one pass

	// Views into mem, in this order:
	b         []block             // the memory-cost matrix
	lanes     []laneScratch       // one per lane
	h0        *[h0Length]byte     // H0 plus the two 4-byte counters initBlocks appends
	block0    *[1024]byte         // H' output for the first two blocks, then extractKey's fold
	hashIn    *[4 + 1024]byte     // H' input: 4-byte length prefix + up to one block
	hashState *[blake2b.Size]byte // H' chaining value for outputs over 64 bytes
	initInput []byte              // initInputReserve bytes for the H0 input
}

const fixedScratch = h0Length + 1024 + (4 + 1024) + blake2b.Size + initInputReserve

// WorkspaceSize is the number of bytes [Bind] needs for the given cost
// parameters: the adjusted matrix, the per-lane scratch and the fixed
// scratch.
func WorkspaceSize(memory uint32, threads uint8) int {
	return int(adjustMemory(memory, threads))*1024 + int(threads)*int(unsafe.Sizeof(laneScratch{})) + fixedScratch
}

// Bind lays a Workspace over mem, which must be at least
// WorkspaceSize(memory, threads) bytes, 8-byte aligned, and all zero (a
// fresh mapping, or a region a previous Bind's Wipe left). Nothing is
// copied: the derivation runs in mem, so a locked mapping keeps the whole
// working state locked. threads must be at least 1 (a zero panics, as
// upstream would).
func Bind(mem []byte, memory uint32, threads uint8) *Workspace {
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	need := WorkspaceSize(memory, threads)
	if len(mem) < need {
		panic("argon2: workspace region too small")
	}
	//nolint:gosec // G103: reading the region's address for the alignment check only.
	if uintptr(unsafe.Pointer(&mem[0]))%8 != 0 {
		panic("argon2: workspace region not 8-byte aligned")
	}
	adjusted := adjustMemory(memory, threads)
	ws := &Workspace{requested: memory, memory: adjusted, threads: uint32(threads), mem: mem[:need]}
	off := 0
	//nolint:gosec // G103: typed views over a caller-owned region whose size and alignment were checked above.
	ws.b = unsafe.Slice((*block)(unsafe.Pointer(&mem[off])), adjusted)
	off += int(adjusted) * 1024
	//nolint:gosec // G103: as above.
	ws.lanes = unsafe.Slice((*laneScratch)(unsafe.Pointer(&mem[off])), threads)
	off += int(threads) * int(unsafe.Sizeof(laneScratch{}))
	ws.h0 = (*[h0Length]byte)(mem[off : off+h0Length])
	off += h0Length
	ws.block0 = (*[1024]byte)(mem[off : off+1024])
	off += 1024
	ws.hashIn = (*[4 + 1024]byte)(mem[off : off+4+1024])
	off += 4 + 1024
	ws.hashState = (*[blake2b.Size]byte)(mem[off : off+blake2b.Size])
	off += blake2b.Size
	ws.initInput = mem[off : off+initInputReserve : off+initInputReserve]
	return ws
}

// adjustMemory returns the memory parameter Argon2 actually uses for the
// given request: rounded down to a multiple of 4*threads and raised to the
// minimum of 8*threads, exactly as upstream does after hashing the
// requested value into H0.
func adjustMemory(memory uint32, threads uint8) uint32 {
	p := uint32(threads)
	memory = memory / (syncPoints * p) * (syncPoints * p)
	if memory < 2*syncPoints*p {
		memory = 2 * syncPoints * p
	}
	return memory
}

// NewWorkspace allocates a zeroed heap Workspace for the given cost
// parameters: [Bind] over a fresh make, which the allocator 8-byte aligns.
// threads must be at least 1 (the caller validates; a zero here panics as
// upstream would). memory is in KiB.
func NewWorkspace(memory uint32, threads uint8) *Workspace {
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	return Bind(make([]byte, WorkspaceSize(memory, threads)), memory, threads)
}

// Wipe zeroes the whole region — the matrix, the lane scratch, H0, the H'
// buffers and the H0 input — in one pass of secmem's non-elidable,
// cache-flushing wipe, so the Workspace is ready for another derivation.
func (ws *Workspace) Wipe() {
	secmem.SecureWipe(ws.mem)
}

// Derive computes an Argon2 tag of len(out) bytes into out, using the
// Workspace's memory and parallelism and the given number of passes.
// secret (K) and data (X) are the RFC 9106 optional inputs; nil means
// absent, which is what upstream's Key/IDKey always pass.
//
// Preconditions, all checked here and all panics (the exported wrapper in
// secmemcrypto turns them into errors first): time ≥ 1, len(out) ≥ 1, a
// known mode, ws non-nil and freshly allocated or wiped.
//
// On return every working value has been overwritten except what is in ws,
// which the caller wipes. The output equals upstream's for the same inputs.
func Derive(out []byte, mode Mode, password, salt, secret, data []byte, time uint32, ws *Workspace) {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if len(out) < 1 {
		panic("argon2: tag length too small")
	}
	if mode > ModeID {
		panic("argon2: unknown mode")
	}
	if ws == nil {
		panic("argon2: nil workspace")
	}
	//nolint:gosec // G115: len(out) is bounded by the caller to uint32 range.
	keyLen := uint32(len(out))

	// secmem: the H0 input normally lives in the workspace's reserve; an
	// input that does not fit gets a heap buffer, allocated here, before
	// the Scrub window, so that on a runtime/secret build it is not
	// registered for GC-time erasure (initHash wipes it explicitly).
	in := ws.h0Input(24 + 4*4 + len(password) + len(salt) + len(secret) + len(data))

	// secmem: the parent's two phases run under secmem.Scrub so that the
	// stack temporaries of BLAKE2b (checkSum's block copy, the returned
	// digest values) and of this package's own helpers are erased on the
	// way out, and the vector registers — which BLAKE2b's AVX2 code and the
	// memmove of the password leave dirty, and which the legacy Scrub does
	// not clear — are cleared inside the window. The OS-thread pin is for
	// the legacy path: runtime/secret pins for the duration of Do itself,
	// but the legacy Scrub does not, and a clear only helps on the thread
	// that holds the residue.
	runtime.LockOSThread()
	secmem.Scrub(func() {
		ws.initHash(in, password, salt, secret, data, time, keyLen, mode)
		ws.initBlocks()
		clearVectorRegs()
	})
	runtime.UnlockOSThread()

	ws.processBlocks(mode, time)

	runtime.LockOSThread()
	secmem.Scrub(func() {
		ws.extractKey(out)
		clearVectorRegs()
	})
	runtime.UnlockOSThread()
}

// h0Input returns a buffer of n bytes for the H0 input: the workspace's
// reserve when it fits, otherwise a heap buffer for this call.
func (ws *Workspace) h0Input(n int) []byte {
	if n <= cap(ws.initInput) {
		return ws.initInput[:n]
	}
	return make([]byte, n)
}

// initHash computes H0 into ws.h0[:64] from the input assembled in `in`
// (len(in) must be exactly the encoded size). secmem: the input is
// assembled in caller-owned memory and hashed with the stack-only
// blake2b.Sum512, rather than streamed into a heap blake2b.New512 digest
// whose block buffer would keep the password, and is wiped here.
func (ws *Workspace) initHash(in, password, salt, key, data []byte, time, keyLen uint32, mode Mode) {

	binary.LittleEndian.PutUint32(in[0:4], ws.threads)
	binary.LittleEndian.PutUint32(in[4:8], keyLen)
	binary.LittleEndian.PutUint32(in[8:12], ws.requested) // pre-adjustment, as upstream hashes it
	binary.LittleEndian.PutUint32(in[12:16], time)
	binary.LittleEndian.PutUint32(in[16:20], uint32(Version))
	binary.LittleEndian.PutUint32(in[20:24], uint32(mode))
	off := 24
	for _, part := range [][]byte{password, salt, key, data} {
		//nolint:gosec // G115: upstream stores these lengths as uint32 too.
		binary.LittleEndian.PutUint32(in[off:off+4], uint32(len(part)))
		off += 4
		off += copy(in[off:], part)
	}

	sum := blake2b.Sum512(in)
	copy(ws.h0[:blake2b.Size], sum[:])
	secmem.SecureWipe(sum[:])
	secmem.SecureWipe(in)
}

// initBlocks fills the first two blocks of every lane from H0.
func (ws *Workspace) initBlocks() {
	h0 := ws.h0
	block0 := ws.block0
	B := ws.b
	memory, threads := ws.memory, ws.threads
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		ws.blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		ws.blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
}

func (ws *Workspace) processBlocks(mode Mode, time uint32) {
	memory, threads := ws.memory, ws.threads
	lanes := memory / threads
	segments := lanes / syncPoints

	var wg sync.WaitGroup // secmem: one for the derivation; reuse after Wait is legal
	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go ws.runSegment(mode, n, slice, lane, time, lanes, segments, &ws.lanes[lane], &wg)
			}
			wg.Wait()
		}
	}
}

// runSegment is the worker goroutine's body: processSegment inside a Scrub
// window of its own.
//
// secmem: runtime/secret.Do does not extend to goroutines the wrapped
// function spawns — but a goroutine may call Do on itself, and that is
// what this is. Inside the window, on a GOEXPERIMENT=runtimesecret build,
// the runtime refuses to asynchronously preempt this goroutine (a
// preemption would copy the register file, block rows included, into
// runtime-owned buffers) and erases the goroutine's stack and registers
// when the window closes. On the legacy path Scrub reserves and then wipes
// a 32 KiB band of this stack in place, which covers processBlock's frame,
// blamkaGeneric's spilled words and the frame an asynchronous preemption
// pushes; asynchronous preemption itself is not prevented there (on Linux
// the legacy window blocks the signal; on Windows and Darwin it cannot).
// The vector-register clear at the end is the legacy path's supplement for
// what runtime/secret does itself, and the OS-thread pin makes it land on
// the thread that did the work.
func (ws *Workspace) runSegment(mode Mode, n, slice, lane, time, lanes, segments uint32, s *laneScratch, wg *sync.WaitGroup) {
	defer wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	secmem.Scrub(func() {
		if segmentProbe != nil {
			segmentProbe()
		}
		ws.processSegment(mode, n, slice, lane, time, lanes, segments, s)
		clearVectorRegs()
	})
}

// segmentProbe, when non-nil, is called inside every worker's Scrub window
// before the segment runs. It exists for one test: proving, on a
// runtime/secret build, that the window a worker opens on itself is real
// (secret.Enabled() is true there), which is the claim the whole worker
// design rests on and which nothing outside the window can observe. nil in
// production; the check is one predictable branch per segment.
var segmentProbe func() //nolint:gochecknoglobals // test hook, nil outside tests

// processSegment is upstream's closure of the same name, with its three
// block locals (and blamka's temporary) replaced by the caller-owned
// laneScratch s; its own stack state is a handful of scalars, and what its
// callees leave below it is covered by runSegment's window.
func (ws *Workspace) processSegment(mode Mode, n, slice, lane, time, lanes, segments uint32, s *laneScratch) {
	B := ws.b
	memory, threads := ws.memory, ws.threads
	addresses, in := &s.addresses, &s.in

	// secmem: upstream's `in` is a fresh zeroed stack local for every
	// segment, so its in[6] block counter restarts at zero each time. The
	// hoisted scratch persists across the segments of a lane, so restore
	// that starting state explicitly. (addresses is always generated before
	// it is read, so it needs no reset.)
	*in = block{}

	if mode == ModeI || (mode == ModeID && n == 0 && slice < syncPoints/2) {
		in[0] = uint64(n)
		in[1] = uint64(lane)
		in[2] = uint64(slice)
		in[3] = uint64(memory)
		in[4] = uint64(time)
		in[5] = uint64(mode)
	}

	index := uint32(0)
	if n == 0 && slice == 0 {
		index = 2 // we have already generated the first two blocks
		if mode == ModeI || mode == ModeID {
			in[6]++
			processBlock(addresses, in, &zeroBlock, s)
			processBlock(addresses, addresses, &zeroBlock, s)
		}
	}

	offset := lane*lanes + slice*segments + index
	var random uint64
	for index < segments {
		prev := offset - 1
		if index == 0 && slice == 0 {
			prev += lanes // last block in lane
		}
		if mode == ModeI || (mode == ModeID && n == 0 && slice < syncPoints/2) {
			if index%blockLength == 0 {
				in[6]++
				processBlock(addresses, in, &zeroBlock, s)
				processBlock(addresses, addresses, &zeroBlock, s)
			}
			random = addresses[index%blockLength]
		} else {
			random = B[prev][0]
		}
		newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
		processBlockXOR(&B[offset], &B[prev], &B[newOffset], s)
		index, offset = index+1, offset+1
	}
}

// extractKey folds the last block of every lane into the last block of the
// matrix and hashes it to len(out) bytes. secmem: the byte-serialised block
// lives in ws.block0 rather than a stack local.
func (ws *Workspace) extractKey(out []byte) {
	B := ws.b
	memory, threads := ws.memory, ws.threads
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}

	block := ws.block0
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	ws.blake2bHash(out, block[:])
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	//nolint:gosec // G115: the modulo keeps the value below lanes, a uint32.
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}
