// Package secmem is a minimal stand-in for github.com/deadpoets/secmem, used by
// the analysistest fixtures so the analyzer's type-aware matching resolves the
// borrowing accessors to the real package path.
package secmem

type SecureBuffer struct{}

func (b *SecureBuffer) WithBytes(fn func([]byte)) error          { return nil }
func (b *SecureBuffer) WithBytesErr(fn func([]byte) error) error { return nil }
func (b *SecureBuffer) CopyOut(dst []byte, off int) (int, error) { return 0, nil }
func (b *SecureBuffer) CopyIn(src []byte, off int) (int, error)  { return 0, nil }
func (b *SecureBuffer) ConstantTimeEqual(o []byte) (bool, error) { return false, nil }
func (b *SecureBuffer) ExposeString() (string, error)            { return "", nil }
func (b *SecureBuffer) Seal() error                              { return nil }
func (b *SecureBuffer) Destroy() error                           { return nil }

// Lock-taking inspectors and the exclusive-lock mutator. Present so the
// reentrancy fixtures can call them: SetByteAt takes the write lock, the rest
// take the read lock, and all of them are unsafe from inside a borrow.
func (b *SecureBuffer) SetByteAt(i int, v byte) error { return nil }
func (b *SecureBuffer) ByteAt(i int) (byte, error)    { return 0, nil }
func (b *SecureBuffer) Len() int                      { return 0 }
func (b *SecureBuffer) MappedLen() int                { return 0 }
func (b *SecureBuffer) IsSealed() bool                { return false }
func (b *SecureBuffer) IsDestroyed() bool             { return false }

type Secret struct{}

func (s Secret) WithBytes(fn func([]byte)) error { return nil }

func NewBuffer(raw []byte) (*SecureBuffer, error) { return &SecureBuffer{}, nil }

func SecureWipe(b []byte) {}

// SecureArena / ArenaSlot mirror the core's locking: a slot borrow holds the
// arena's read lock; Destroy, ReadOnly and ReadWrite take its exclusive lock;
// Acquire and LiveCount take only the allocation mutex.
type SecureArena struct{}

func (a *SecureArena) Acquire() (*ArenaSlot, error) { return &ArenaSlot{}, nil }
func (a *SecureArena) Destroy() error               { return nil }
func (a *SecureArena) ReadOnly() error              { return nil }
func (a *SecureArena) ReadWrite() error             { return nil }
func (a *SecureArena) LiveCount() int               { return 0 }
func (a *SecureArena) IsDestroyed() bool            { return false }

type ArenaSlot struct{}

func (s *ArenaSlot) WithBytes(fn func([]byte)) error          { return nil }
func (s *ArenaSlot) WithBytesErr(fn func([]byte) error) error { return nil }
func (s *ArenaSlot) Release() error                           { return nil }
func (s *ArenaSlot) IsLive() bool                             { return true }

func NewArena(slotSize, count int) (*SecureArena, error) { return &SecureArena{}, nil }
