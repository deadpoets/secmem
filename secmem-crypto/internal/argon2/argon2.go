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

// laneScratch is the per-lane working state that upstream keeps as stack
// locals of each processSegment goroutine. secmem: hoisted here so the
// parent owns it — a worker goroutine's stack is reachable by nothing after
// it exits, and the runtime hands it to the next goroutine unwiped.
//
// zero must be all-zero on entry to every segment: it is the constant zero
// block the data-independent address generator XORs against, and the SSE
// mix step also uses it as its "previous t" input (upstream relied on a
// freshly zeroed stack local for that). Wipe restores the invariant.
type laneScratch struct {
	addresses, in, zero, tmp block
}

// Workspace holds every byte of working state one derivation touches. Its
// zero value is not usable; obtain one from [NewWorkspace]. A Workspace may
// be reused across derivations with the same memory and threads, and must
// be [Workspace.Wipe]d between them (and after the last one) — Derive does
// not wipe on the caller's behalf, so that a test can inspect the residue
// (and prove it absent) after the call.
type Workspace struct {
	requested uint32 // the memory parameter as given: it is what H0 commits to
	memory    uint32 // adjusted: a multiple of syncPoints*threads, ≥ 2*syncPoints*threads
	threads   uint32

	// Heap allocations, all wiped by Wipe:
	b     []block       // the memory-cost matrix
	lanes []laneScratch // one per lane

	// Fixed-size scratch, embedded so it is part of the same allocation:
	h0        [h0Length]byte // H0 plus the two 4-byte counters initBlocks appends
	block0    [1024]byte     // H' output for the first two blocks, then extractKey's fold
	hashIn    [4 + 1024]byte // H' input: 4-byte length prefix + up to one block
	hashState [blake2b.Size]byte

	// H0 input (params ‖ len‖password ‖ len‖salt ‖ len‖K ‖ len‖X). Sized per
	// call because the password length is the caller's; grown, never shrunk.
	initInput []byte
}

// AdjustedMemory returns the memory parameter Argon2 actually uses for the
// given request: rounded down to a multiple of 4*threads and raised to the
// minimum of 8*threads, exactly as upstream does.
func AdjustedMemory(memory uint32, threads uint8) uint32 {
	p := uint32(threads)
	memory = memory / (syncPoints * p) * (syncPoints * p)
	if memory < 2*syncPoints*p {
		memory = 2 * syncPoints * p
	}
	return memory
}

// NewWorkspace allocates a zeroed Workspace for the given cost parameters.
// threads must be at least 1 (the caller validates; a zero here panics as
// upstream would). memory is in KiB and is adjusted per [AdjustedMemory].
func NewWorkspace(memory uint32, threads uint8) *Workspace {
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	adjusted := AdjustedMemory(memory, threads)
	return &Workspace{
		requested: memory,
		memory:    adjusted,
		threads:   uint32(threads),
		b:         make([]block, adjusted),
		lanes:     make([]laneScratch, threads),
	}
}

// Memory reports the adjusted memory cost in KiB (one block each).
func (ws *Workspace) Memory() uint32 { return ws.memory }

// Wipe zeroes every byte of working state — the matrix, the lane scratch,
// H0, the H' buffers and the H0 input — using secmem's non-elidable wipe.
// It restores the all-zero invariant NewWorkspace established, so the
// Workspace is ready for another derivation.
func (ws *Workspace) Wipe() {
	if len(ws.b) > 0 {
		//nolint:gosec // G103: byte view of a Go-owned []block for the wipe; audited.
		secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Pointer(&ws.b[0])), len(ws.b)*int(unsafe.Sizeof(block{}))))
	}
	if len(ws.lanes) > 0 {
		//nolint:gosec // G103: byte view of a Go-owned []laneScratch for the wipe; audited.
		secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Pointer(&ws.lanes[0])), len(ws.lanes)*int(unsafe.Sizeof(laneScratch{}))))
	}
	secmem.SecureWipe(ws.h0[:])
	secmem.SecureWipe(ws.block0[:])
	secmem.SecureWipe(ws.hashIn[:])
	secmem.SecureWipe(ws.hashState[:])
	secmem.SecureWipe(ws.initInput[:cap(ws.initInput)])
}

// Derive computes an Argon2 tag of len(out) bytes into out, using the
// Workspace's memory and parallelism and the given number of passes.
// secret (K) and data (X) are the RFC 9106 optional inputs; nil means
// absent, which is what upstream's Key/IDKey always pass.
//
// Preconditions (the exported wrapper in secmemcrypto enforces them as
// errors; here they panic exactly as upstream does): time ≥ 1, len(out) ≥ 1,
// ws non-nil and all-zero.
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
	if ws == nil {
		panic("argon2: nil workspace")
	}
	//nolint:gosec // G115: len(out) is bounded by the caller to uint32 range.
	keyLen := uint32(len(out))

	// secmem: the goroutine-free phases run under secmem.Scrub so that the
	// stack temporaries of BLAKE2b's one-shot functions (checkSum's block
	// copy, the returned digest values) and of this package's own helpers
	// are erased on the way out. processBlocks is deliberately outside: it
	// spawns goroutines, which Scrub does not reach — that is what the
	// hoisted laneScratch is for.
	secmem.Scrub(func() {
		ws.initHash(password, salt, secret, data, time, keyLen, mode)
		ws.initBlocks()
	})
	ws.processBlocks(mode, time)
	secmem.Scrub(func() {
		ws.extractKey(out)
	})
	// secmem: BLAKE2b's AVX2 path and the SSE blamka leave block state in
	// the vector registers of whichever thread ran them; the parent ran
	// initBlocks/extractKey on this one.
	clearVectorRegs()
}

// initHash computes H0 into ws.h0[:64]. secmem: the input is assembled in
// ws.initInput and hashed with the stack-only blake2b.Sum512, rather than
// streamed into a heap blake2b.New512 digest whose block buffer would keep
// the password.
func (ws *Workspace) initHash(password, salt, key, data []byte, time, keyLen uint32, mode Mode) {
	need := 24 + 4*4 + len(password) + len(salt) + len(key) + len(data)
	if cap(ws.initInput) < need {
		ws.initInput = make([]byte, need)
	}
	in := ws.initInput[:need]

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
	h0 := &ws.h0
	block0 := &ws.block0
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

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go ws.processSegment(mode, n, slice, lane, time, lanes, segments, &ws.lanes[lane], &wg)
			}
			wg.Wait()
		}
	}
}

// processSegment is upstream's closure of the same name, with its three
// block locals (and blamka's temporary) replaced by the caller-owned
// laneScratch s. Its only stack state is a handful of scalars.
func (ws *Workspace) processSegment(mode Mode, n, slice, lane, time, lanes, segments uint32, s *laneScratch, wg *sync.WaitGroup) {
	defer wg.Done()
	// secmem: the blamka SSE code leaves block words in XMM registers on
	// whatever thread ran this goroutine; clear them before the goroutine
	// exits and the thread moves on. Deferred so it runs even if the loop
	// panics (which is fatal to the process anyway, but the order is right).
	defer clearVectorRegs()

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
			processBlock(addresses, in, &s.zero, s)
			processBlock(addresses, addresses, &s.zero, s)
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
				processBlock(addresses, in, &s.zero, s)
				processBlock(addresses, addresses, &s.zero, s)
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

	block := &ws.block0
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
