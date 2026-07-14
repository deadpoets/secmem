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

type Secret struct{}

func (s Secret) WithBytes(fn func([]byte)) error { return nil }

func NewBuffer(raw []byte) (*SecureBuffer, error) { return &SecureBuffer{}, nil }
