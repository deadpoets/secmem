// argon2_workspace.go: Argon2 with its working state in locked memory,
// reused across derivations.
//
// [Argon2Into] wipes Argon2's working state after every call, but during
// the call that state is ordinary Go heap: pageable, part of a core dump,
// and unknown to secmem's registry. [Argon2Workspace] moves the whole
// working set into one [secmem.SecureBuffer] — locked, guard-paged,
// excluded from dumps where the platform allows, registered for the
// emergency wipes — and keeps it for reuse, because a locked 64 MiB
// mapping costs more to create and destroy than the derivation itself.
// [Argon2Pool] holds several for concurrent callers with a fixed ceiling on
// locked memory.
//
// Neither falls back to the heap. A host whose lock budget cannot hold the
// workspace fails at construction, before the first login, with the
// platform's error; raise the budget with [secmem.EnsureMemlockLimit] at
// startup, as for any other large SecureBuffer. A caller that wants the
// heap behaviour has [Argon2Into], and is told by that function's doc what
// it does not get.
package secmemcrypto

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/argon2"
)

// Argon2Workspace is a locked, reusable working set for one Argon2 cost
// profile. Create one with [NewArgon2Workspace], derive with
// [Argon2Workspace.Derive] as many times as needed, and [Destroy] it when
// done. One derivation runs at a time; concurrent Derive calls queue.
//
// Between derivations the region holds zeros: every Derive ends with
// secmem's cache-flushing wipe over the whole region, whether or not it
// succeeded, so an idle workspace carries nothing. Destroy applies the
// SecureBuffer's full wipe and unmaps.
type Argon2Workspace struct {
	mem     *secmem.SecureBuffer
	memory  uint32
	threads uint8
	mu      sync.Mutex
}

// NewArgon2Workspace allocates a locked workspace for the given cost
// profile (memory in KiB, threads lanes; the same rounding as
// [Argon2Params]). It fails, rather than degrading to the heap, when the
// process cannot lock that much memory: the error wraps the platform's.
func NewArgon2Workspace(memory uint32, threads uint8) (*Argon2Workspace, error) {
	if threads < 1 {
		return nil, fmt.Errorf("secmemcrypto: argon2 workspace: threads (parallelism) must be >= 1, got %d", threads)
	}
	if uint64(memory)*1024 > math.MaxInt-1<<20 {
		return nil, fmt.Errorf("secmemcrypto: argon2 workspace: memory %d KiB exceeds the address space", memory)
	}
	buf, err := secmem.NewEmptyBuffer(argon2.WorkspaceSize(memory, threads))
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: argon2 workspace: %w", err)
	}
	return &Argon2Workspace{mem: buf, memory: memory, threads: threads}, nil
}

// Size is the number of locked bytes the workspace holds.
func (w *Argon2Workspace) Size() int { return w.mem.Len() }

// Derive is [Argon2Into] with the derivation's working state in this
// workspace instead of a fresh heap allocation. p.Memory and p.Threads must
// equal the values the workspace was created with; p.Mode, p.Time, p.Secret
// and p.Data are free per call. Everything [Argon2Into] documents about
// output, validation and the borrow of out holds here too.
//
// Two SecureBuffers are borrowed for the call, the workspace's and out;
// they are acquired in ascending [secmem.SecureBuffer.LockOrder], the
// module's rule for every two-buffer operation, so Derive cannot deadlock
// against another ordered borrow. If the password or Secret is itself
// borrowed from a third SecureBuffer, that outer borrow is the caller's,
// and must come first in LockOrder.
func (w *Argon2Workspace) Derive(password, salt []byte, p Argon2Params, out *secmem.SecureBuffer) error {
	mode, err := validateArgon2(password, salt, p, out)
	if err != nil {
		return err
	}
	if p.Memory != w.memory || p.Threads != w.threads {
		return fmt.Errorf("secmemcrypto: argon2 workspace: params memory=%d threads=%d do not match the workspace (memory=%d threads=%d)",
			p.Memory, p.Threads, w.memory, w.threads)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	first, second := w.mem, out
	if first.LockOrder() > second.LockOrder() {
		first, second = second, first
	}
	err = first.WithBytesErr(func(a []byte) error {
		return second.WithBytesErr(func(b []byte) error {
			region, dst := a, b
			if first != w.mem {
				region, dst = b, a
			}
			ws := argon2.Bind(region, w.memory, w.threads)
			defer ws.Wipe()
			argon2.Derive(dst, mode, password, salt, p.Secret, p.Data, p.Time, ws)
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: argon2 derive: %w", err)
	}
	return nil
}

// Destroy wipes and unmaps the workspace. It waits for an in-flight
// derivation to finish. Derive after Destroy returns an error wrapping
// [secmem.ErrDestroyed].
func (w *Argon2Workspace) Destroy() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mem.Destroy()
}

// Argon2Pool is a fixed set of [Argon2Workspace]s for concurrent callers.
// Its size is the ceiling on simultaneous derivations and therefore on
// locked memory (size × [Argon2Workspace.Size]); a Derive that finds every
// workspace busy waits for one. All workspaces are allocated up front, so
// a lock budget that cannot hold the pool fails in [NewArgon2Pool], not on
// a later request.
type Argon2Pool struct {
	free chan *Argon2Workspace
	all  []*Argon2Workspace
	mu   sync.Mutex
	done bool
}

// NewArgon2Pool allocates size locked workspaces for the given cost
// profile. On any failure the workspaces already allocated are destroyed
// and the error is returned.
func NewArgon2Pool(size int, memory uint32, threads uint8) (*Argon2Pool, error) {
	if size < 1 {
		return nil, fmt.Errorf("secmemcrypto: argon2 pool: size must be >= 1, got %d", size)
	}
	p := &Argon2Pool{free: make(chan *Argon2Workspace, size)}
	for i := 0; i < size; i++ {
		ws, err := NewArgon2Workspace(memory, threads)
		if err != nil {
			_ = p.Destroy()
			return nil, fmt.Errorf("secmemcrypto: argon2 pool: workspace %d of %d: %w", i+1, size, err)
		}
		p.all = append(p.all, ws)
		p.free <- ws
	}
	return p, nil
}

// Len is the number of workspaces in the pool.
func (p *Argon2Pool) Len() int { return len(p.all) }

// Derive runs [Argon2Workspace.Derive] on the first free workspace, waiting
// for one if all are busy.
func (p *Argon2Pool) Derive(password, salt []byte, params Argon2Params, out *secmem.SecureBuffer) error {
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done {
		return fmt.Errorf("secmemcrypto: argon2 pool: %w", secmem.ErrDestroyed)
	}
	ws, ok := <-p.free
	if !ok {
		return fmt.Errorf("secmemcrypto: argon2 pool: %w", secmem.ErrDestroyed)
	}
	defer func() { p.free <- ws }()
	return ws.Derive(password, salt, params, out)
}

// Destroy waits for in-flight derivations, then destroys every workspace.
// It returns the first destroy error, if any; Derive after Destroy returns
// an error wrapping [secmem.ErrDestroyed].
func (p *Argon2Pool) Destroy() error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return nil
	}
	p.done = true
	p.mu.Unlock()

	// Take every workspace back; each receive waits for one in-flight
	// derivation to return its workspace. A Derive that raced past the done
	// check and took a workspace returns it here too, so nothing is left
	// out and the channel can be closed without a send racing it.
	for range p.all {
		<-p.free
	}
	close(p.free)

	var first error
	for _, ws := range p.all {
		if err := ws.Destroy(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// validateArgon2 is the parameter check shared by [Argon2Into] and
// [Argon2Workspace.Derive]: every input the functions can check is an
// error, never a panic.
func validateArgon2(password, salt []byte, p Argon2Params, out *secmem.SecureBuffer) (argon2.Mode, error) {
	if out == nil {
		return 0, errors.New("secmemcrypto: nil output buffer")
	}
	if out.IsDestroyed() {
		return 0, fmt.Errorf("secmemcrypto: argon2 derive: %w", secmem.ErrDestroyed)
	}
	if p.Time < 1 {
		return 0, fmt.Errorf("secmemcrypto: argon2 derive: time (passes) must be >= 1, got %d", p.Time)
	}
	if p.Threads < 1 {
		return 0, fmt.Errorf("secmemcrypto: argon2 derive: threads (parallelism) must be >= 1, got %d", p.Threads)
	}
	var mode argon2.Mode
	switch p.Mode {
	case Argon2id:
		mode = argon2.ModeID
	case Argon2i:
		mode = argon2.ModeI
	case Argon2d:
		mode = argon2.ModeD
	default:
		return 0, fmt.Errorf("secmemcrypto: argon2 derive: unknown mode %d", p.Mode)
	}
	size := out.Len()
	if size <= 0 {
		return 0, errors.New("secmemcrypto: empty output buffer")
	}
	if uint64(size) > math.MaxUint32 {
		return 0, fmt.Errorf("secmemcrypto: output too large: %d", size)
	}
	for _, in := range []struct {
		name string
		b    []byte
	}{{"password", password}, {"salt", salt}, {"secret", p.Secret}, {"data", p.Data}} {
		if uint64(len(in.b)) > math.MaxUint32 {
			return 0, fmt.Errorf("secmemcrypto: argon2 derive: %s too long: %d bytes", in.name, len(in.b))
		}
	}
	// The matrix is Memory KiB of 1 KiB blocks; on a 32-bit platform a
	// large request overflows int before make can refuse it.
	if uint64(p.Memory)*1024 > math.MaxInt-1<<20 {
		return 0, fmt.Errorf("secmemcrypto: argon2 derive: memory %d KiB exceeds the address space", p.Memory)
	}
	return mode, nil
}
