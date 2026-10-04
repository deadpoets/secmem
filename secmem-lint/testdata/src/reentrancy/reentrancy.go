package reentrancy

import (
	"crypto"

	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

func sameBufferMethod(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		buf.ExposeString() // want `secmem-lint: ExposeString called on the same buffer`
	})
}

func sameBufferNested(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		_ = buf.WithBytesErr(func(c []byte) error { // want `secmem-lint: WithBytesErr called on the same buffer`
			return nil
		})
	})
}

// differentBufferOK is the documented decrypt-into pattern: nesting access to a
// DIFFERENT buffer is legal and must not be flagged.
func differentBufferOK(key, out *secmem.SecureBuffer) {
	_ = key.WithBytesErr(func(k []byte) error {
		_ = k
		return out.WithBytesErr(func(o []byte) error {
			_ = o
			return nil
		})
	})
}

// sameBufferLockingInspectors covers the members added after the review: the
// exclusive-lock mutator and the rLock inspectors. SetByteAt self-deadlocks
// outright; the inspectors deadlock as soon as a writer queues between the two
// read acquires, because the lock is writer-preferring.
func sameBufferLockingInspectors(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = b
		_ = buf.SetByteAt(0, 1)         // want `secmem-lint: SetByteAt called on the same buffer`
		_ = buf.Len()                   // want `secmem-lint: Len called on the same buffer`
		_ = buf.MappedLen()             // want `secmem-lint: MappedLen called on the same buffer`
		_ = buf.IsSealed()              // want `secmem-lint: IsSealed called on the same buffer`
		_ = buf.IsDestroyed()           // want `secmem-lint: IsDestroyed called on the same buffer`
		_, _ = buf.ConstantTimeEqual(b) // want `secmem-lint: ConstantTimeEqual called on the same buffer`
	})
}

// vault holds its buffer in a struct field, which is how any program larger
// than an example holds it. The check used to require a plain identifier on
// both ends, so every one of these was silently clean.
type vault struct {
	buf   *secmem.SecureBuffer
	inner struct{ buf *secmem.SecureBuffer }
}

func (v *vault) fieldReceiver() {
	_ = v.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.buf.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

func (v *vault) nestedFieldReceiver() {
	_ = v.inner.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.inner.buf.IsSealed() // want `secmem-lint: IsSealed called on the same buffer`
	})
}

// differentFieldOK: a different field is a different buffer, so the
// decrypt-into pattern still has to survive the wider receiver matching.
func (v *vault) differentFieldOK() {
	_ = v.buf.WithBytes(func(b []byte) {
		_ = b
		_ = v.inner.buf.Len()
	})
}

// indexedReceiverNotDecidable: bufs[i] and bufs[j] are written alike and need
// not be the same buffer, so receivers that are index expressions are left
// alone rather than guessed at.
func indexedReceiverNotDecidable(bufs []*secmem.SecureBuffer) {
	_ = bufs[0].WithBytes(func(b []byte) {
		_ = b
		_ = bufs[1].Len()
	})
}

// --- aliases and method values ---

func aliasInside(buf *secmem.SecureBuffer) {
	b2 := buf
	_ = buf.WithBytes(func(b []byte) {
		_ = b2.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

func aliasAsReceiver(buf *secmem.SecureBuffer) {
	b2 := buf
	_ = b2.WithBytes(func(b []byte) {
		_ = buf.IsSealed() // want `secmem-lint: IsSealed called on the same buffer`
	})
}

func (v *vault) fieldAlias() {
	x := v.buf
	_ = v.buf.WithBytes(func(b []byte) {
		_ = x.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

func methodValue(buf *secmem.SecureBuffer) {
	l := buf.Len
	_ = buf.WithBytes(func(b []byte) {
		_ = l() // want `secmem-lint: Len called on the same buffer`
	})
}

// reassignedAliasNotFollowed: an alias written twice is left alone.
func reassignedAliasNotFollowed(buf, other *secmem.SecureBuffer, cond bool) {
	b2 := other
	if cond {
		b2 = buf
	}
	_ = buf.WithBytes(func(b []byte) {
		_ = b2.Len()
	})
}

// --- synchronous vs deferred execution ---

func syncShapes(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		func() { _ = buf.Len() }()          // want `secmem-lint: Len called on the same buffer`
		defer func() { _ = buf.Len() }()    // want `secmem-lint: Len called on the same buffer`
		run(func() { _ = buf.MappedLen() }) // want `secmem-lint: MappedLen called on the same buffer`
	})
}

func run(f func()) { f() }

var later func()

func asyncShapesOK(buf *secmem.SecureBuffer) (fn func()) {
	_ = buf.WithBytes(func(b []byte) {
		later = func() { _ = buf.Len() }
		fn = func() { _ = buf.Len() }
		go func() { _ = buf.Len() }()
	})
	return fn
}

// --- arena slots ---

func slotRelease(slot *secmem.ArenaSlot) {
	_ = slot.WithBytes(func(b []byte) {
		_ = slot.Release() // want `secmem-lint: Release called on the same slot`
	})
}

func slotArenaExclusive(arena *secmem.SecureArena) {
	slot, _ := arena.Acquire()
	_ = slot.WithBytes(func(b []byte) {
		_ = arena.Destroy()    // want `secmem-lint: Destroy called on the slot's arena inside a slot borrow`
		_ = arena.ReadOnly()   // want `secmem-lint: ReadOnly called on the slot's arena inside a slot borrow`
		_ = arena.ReadWrite()  // want `secmem-lint: ReadWrite called on the slot's arena inside a slot borrow`
		_, _ = arena.Acquire() // ok: Acquire takes only the allocation mutex
		_ = arena.LiveCount()  // ok
	})
}

// slotOtherArenaOK: a different arena's exclusive lock is not held by this
// borrow.
func slotOtherArenaOK(arena, other *secmem.SecureArena) {
	slot, _ := arena.Acquire()
	_ = slot.WithBytes(func(b []byte) {
		_ = other.Destroy()
	})
}

// slotUnknownArenaDefaultSilent: the slot is a parameter, so its arena is not
// known; default mode stays silent (strict mode reports — see strict).
func slotUnknownArenaDefaultSilent(slot *secmem.ArenaSlot, arena *secmem.SecureArena) {
	_ = slot.WithBytes(func(b []byte) {
		_ = arena.Destroy()
	})
}

// --- embedded buffers ---

type embeds struct{ *secmem.SecureBuffer }

// embeddedPromotion: the buffer embedded in e is the same buffer whether its
// methods are reached through the promotion (e.Len) or on the field
// (e.SecureBuffer.Len), and whichever spelling the borrow itself uses.
func embeddedPromotion(e embeds) {
	_ = e.WithBytes(func(b []byte) {
		_ = e.Len()              // want `secmem-lint: Len called on the same buffer`
		_ = e.SecureBuffer.Len() // want `secmem-lint: Len called on the same buffer`
	})
	_ = e.SecureBuffer.WithBytes(func(b []byte) {
		_ = e.IsSealed()              // want `secmem-lint: IsSealed called on the same buffer`
		_ = e.SecureBuffer.IsSealed() // want `secmem-lint: IsSealed called on the same buffer`
	})
	x := e.SecureBuffer
	_ = e.WithBytes(func(b []byte) {
		_ = x.Len() // want `secmem-lint: Len called on the same buffer`
	})
}

type twoBuffers struct {
	*secmem.SecureBuffer
	other *secmem.SecureBuffer
}

// embeddedDifferentFieldOK: the promoted buffer and a named field are two
// buffers, so the decrypt-into pattern survives the promotion handling.
func embeddedDifferentFieldOK(t twoBuffers) {
	_ = t.WithBytes(func(b []byte) {
		_ = t.other.Len()
		_ = t.other.WithBytes(func(o []byte) { copy(o, b) })
	})
	_ = t.other.WithBytes(func(b []byte) {
		_ = t.Len()
	})
}

// --- secmem-crypto keys ---

// A key's operations borrow the buffer its accessor already holds: signing,
// key agreement, decapsulation and marshalling each take the read lock again,
// which deadlocks once a writer is queued, and Destroy takes it exclusively.
func signerInsideOwnBorrow(s *secmemcrypto.Ed25519Signer, msg []byte) {
	_ = s.WithSeed(func(seed []byte) error {
		_, _ = s.Sign(nil, msg, crypto.Hash(0))                           // want `secmem-lint: Sign called on the same key inside its own borrowing closure`
		_, _ = s.SignMessage(nil, msg, crypto.Hash(0))                    // want `secmem-lint: SignMessage called on the same key`
		_, _ = s.MarshalOpenSSHPrivateKey("c")                            // want `secmem-lint: MarshalOpenSSHPrivateKey called on the same key`
		_, _ = s.MarshalOpenSSHPrivateKeyWithPassphrase("c", []byte("p")) // want `secmem-lint: MarshalOpenSSHPrivateKeyWithPassphrase called on the same key`
		_ = s.WithSeed(func([]byte) error { return nil })                 // want `secmem-lint: WithSeed called on the same key`
		_ = s.Destroy()                                                   // want `secmem-lint: Destroy called on the same key`
		_ = s.Public()                                                    // ok: the cached public key, no lock
		_ = s.Equal(nil)                                                  // ok
		return nil
	})
}

func otherKeysInsideOwnBorrow(e *secmemcrypto.ECDSASigner, r *secmemcrypto.RSASigner, x *secmemcrypto.X25519Key, m *secmemcrypto.MLKEM768Key, d []byte) {
	_ = e.WithScalar(func([]byte) error {
		_, _ = e.Sign(nil, d, crypto.SHA256) // want `secmem-lint: Sign called on the same key`
		_ = e.Public()                       // ok
		return nil
	})
	_ = r.WithDER(func([]byte) error {
		_, _ = r.Sign(nil, d, crypto.SHA256) // want `secmem-lint: Sign called on the same key`
		_ = r.Public()                       // ok
		return nil
	})
	_ = x.WithScalar(func([]byte) error {
		_, _ = x.PublicKey()              // want `secmem-lint: PublicKey called on the same key`
		_, _ = x.SharedSecret([32]byte{}) // want `secmem-lint: SharedSecret called on the same key`
		_ = x.ConstantTimeEqual(x)        // want `secmem-lint: ConstantTimeEqual called on the same key`
		return nil
	})
	_ = m.WithSeed(func([]byte) error {
		_, _ = m.Decapsulate(d)          // want `secmem-lint: Decapsulate called on the same key`
		_, _ = m.EncapsulationKeyBytes() // ok: captured at construction
		return nil
	})
}

// keyBehindInterface: the same signer reached through an interface is still
// the same key, so the method's name decides.
func keyBehindInterface(s *secmemcrypto.Ed25519Signer, msg []byte) {
	var sg secmemcrypto.Signer = s
	_ = s.WithSeed(func([]byte) error {
		_, _ = sg.Sign(nil, msg, crypto.Hash(0)) // want `secmem-lint: Sign called on the same key`
		_ = sg.Public()                          // ok
		return nil
	})
}

// differentKeyOK: signing with another key inside a borrow is not reentrant.
func differentKeyOK(s, other *secmemcrypto.Ed25519Signer, x *secmemcrypto.X25519Key, msg []byte) {
	_ = s.WithSeed(func([]byte) error {
		_, _ = other.Sign(nil, msg, crypto.Hash(0))
		_, _ = x.PublicKey()
		return nil
	})
}

// lockFreeMethodsOK: the methods that read no locked state are fine inside a
// borrow of the same receiver. Destroy on a Secret is not one of them.
func lockFreeMethodsOK(buf *secmem.SecureBuffer, slot *secmem.ArenaSlot, sec secmem.Secret) {
	_ = buf.WithBytes(func([]byte) {
		_ = buf.LockOrder()
		_ = buf.String()
	})
	_ = slot.WithBytes(func([]byte) {
		_ = slot.Index()
		_ = slot.IsLive()
	})
	_ = sec.WithBytes(func([]byte) {
		_ = sec.String()
		_ = sec.Destroy() // want `secmem-lint: Destroy called on the same buffer`
	})
}
