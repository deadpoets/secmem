// Package secmem is a minimal stand-in for github.com/deadpoets/secmem, used by
// the analysistest fixtures so the analyzer's type-aware matching resolves the
// borrowing accessors to the real package path.
package secmem

type SecureBuffer struct{}

func (b *SecureBuffer) WithBytes(fn func([]byte)) error          { return nil }
func (b *SecureBuffer) WithBytesErr(fn func([]byte) error) error { return nil }
func (b *SecureBuffer) CopyOut(dst []byte, off int) (int, error) { return 0, nil }
func (b *SecureBuffer) CopyIn(src []byte, off int) (int, error)  { return 0, nil }
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
