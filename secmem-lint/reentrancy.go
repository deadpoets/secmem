package secmemlint

import (
	"fmt"
	"go/ast"
	"go/types"
)

// lockUse says what an exported method does with the lock its receiver's
// borrowing accessor holds for the whole callback.
type lockUse int

const (
	// takesLock: the method acquires that lock again. Calling it on the SAME
	// receiver from inside its own borrowing closure violates the documented
	// non-reentrancy contract and deadlocks.
	takesLock lockUse = iota + 1
	// lockFree: the method reads only state fixed at construction, or an
	// atomic, and is safe inside the borrow.
	lockFree
)

// methodLocks classifies every exported method of every secmem and
// secmem-crypto type that has a borrowing accessor, keyed by
// "import/path.Type" and then by method name. The key is the type because a
// name means different things on different types: Destroy on a key and on a
// buffer both take the lock, but ConstantTimeEqual, Sign or PublicKey are
// each one type's method, and Public is lock-free where PublicKey is not.
//
// Both classes are listed, so that a method missing from the table is a
// method nobody has looked at: the table test fails for any exported method
// of these types in the sibling sources that has no entry here.
var methodLocks = map[string]map[string]lockUse{ //nolint:gochecknoglobals // immutable lookup table.
	secmemPkg + ".SecureBuffer": {
		"WithBytes": takesLock, "WithBytesErr": takesLock,
		"CopyOut": takesLock, "CopyIn": takesLock, "ConstantTimeEqual": takesLock,
		"ExposeString": takesLock, "ByteAt": takesLock, "WriteTo": takesLock, "ReadFrom": takesLock,
		"Truncate": takesLock, "Seal": takesLock, "Unseal": takesLock,
		"ReadOnly": takesLock, "ReadWrite": takesLock, "Destroy": takesLock,

		// SetByteAt takes the EXCLUSIVE lock, so calling it inside a borrow
		// is an unconditional self-deadlock — the most certain member of
		// this set.
		"SetByteAt": takesLock,

		// The rLock inspectors. A nested read acquire looks harmless, but
		// the lock is writer-preferring: rLock waits while any writer is
		// queued, so a second read taken from inside a borrow deadlocks as
		// soon as a writer arrives between the two — a Destroy or an
		// emergency wipe is enough. That makes them load-bearing rather than
		// merely untidy.
		"Len": takesLock, "MappedLen": takesLock, "IsSealed": takesLock, "IsDestroyed": takesLock,

		// The backing report and the registration ordinal are fixed at
		// construction; the redaction methods read no fields at all.
		"Capabilities": lockFree, "LockOrder": lockFree,
		"String": lockFree, "GoString": lockFree, "Format": lockFree, "LogValue": lockFree,
	},
	secmemPkg + ".ArenaSlot": {
		"WithBytes": takesLock, "WithBytesErr": takesLock,
		// Release re-takes the arena's read lock that the slot's own borrow
		// already holds — the same writer-preferring hazard as Len.
		"Release": takesLock,

		// Index is a field of the handle and IsLive one atomic load.
		"Index": lockFree, "IsLive": lockFree,
		"String": lockFree, "GoString": lockFree, "Format": lockFree, "LogValue": lockFree,
	},
	secmemPkg + ".Secret": {
		// A Secret forwards to its buffer. ConstantTimeEqual borrows it even
		// when both operands are the same Secret.
		"WithBytes": takesLock, "ConstantTimeEqual": takesLock, "WriteTo": takesLock, "Destroy": takesLock,

		"String": lockFree, "GoString": lockFree, "LogValue": lockFree,
		"MarshalText": lockFree, "MarshalJSON": lockFree,
	},

	// The secmem-crypto keys keep their private half in one SecureBuffer and
	// every operation that needs it borrows that buffer: the accessor
	// itself, signing, key agreement, decapsulation, marshalling. Destroy
	// takes the same lock exclusively. What reads only the public half
	// captured at construction is lock-free.
	cryptoPkg + ".Ed25519Signer": {
		"WithSeed": takesLock, "Destroy": takesLock,
		"Sign": takesLock, "SignMessage": takesLock,
		"MarshalOpenSSHPrivateKey":                     takesLock,
		"MarshalOpenSSHPrivateKeyWithPassphrase":       takesLock,
		"MarshalOpenSSHPrivateKeyWithPassphraseParams": takesLock,

		"Public": lockFree, "Equal": lockFree,
	},
	cryptoPkg + ".ECDSASigner": {
		"WithScalar": takesLock, "Destroy": takesLock, "Sign": takesLock,

		"Public": lockFree, "Equal": lockFree,
	},
	cryptoPkg + ".RSASigner": {
		"WithDER": takesLock, "Destroy": takesLock, "Sign": takesLock,

		"Public": lockFree, "Equal": lockFree,
	},
	cryptoPkg + ".X25519Key": {
		// PublicKey is recomputed from the scalar on every call, unlike the
		// signers' cached Public. ConstantTimeEqual borrows both keys, and
		// on the same key still takes the read lock to inspect it.
		"WithScalar": takesLock, "Destroy": takesLock, "ConstantTimeEqual": takesLock,
		"PublicKey": takesLock, "SharedSecret": takesLock,
	},
	cryptoPkg + ".MLKEM768Key": {
		"WithSeed": takesLock, "Destroy": takesLock, "Decapsulate": takesLock,

		"EncapsulationKeyBytes": lockFree,
	},
}

// lockTakingNames is every method name methodLocks marks takesLock on some
// type. It decides a call through an INTERFACE, where the type behind it is
// not known: a buffer or key held as an interface value is still the same
// one, and its method names are all there is to go on.
var lockTakingNames = func() map[string]bool { //nolint:gochecknoglobals // immutable, derived from methodLocks.
	names := make(map[string]bool)
	for _, methods := range methodLocks {
		for name, use := range methods {
			if use == takesLock {
				names[name] = true
			}
		}
	}
	return names
}()

// takesReceiverLock reports whether m, called on the receiver a borrowing
// closure belongs to, acquires the lock that borrow holds.
func takesReceiverLock(m *types.Func) bool {
	recv := m.Signature().Recv()
	if recv == nil {
		return false
	}
	if types.IsInterface(recv.Type()) {
		return lockTakingNames[m.Name()]
	}
	return methodLocks[namedTypeKey(recv.Type())][m.Name()] == takesLock
}

// arenaLocks classifies the exported methods of SecureArena by what they do
// with the arena lock a slot borrow holds for reading during the whole
// callback. takesLock here means the EXCLUSIVE side (securearena.go:
// mu.lock): calling one of those on the slot's arena from inside the borrow
// is a certain self-deadlock. Acquire and LiveCount take only the allocation
// mutex, which is never held across a callback, and the rest read fields
// fixed at construction or an atomic.
var arenaLocks = map[string]lockUse{ //nolint:gochecknoglobals // immutable lookup table.
	"Destroy": takesLock, "ReadOnly": takesLock, "ReadWrite": takesLock,
	"Acquire": lockFree, "LiveCount": lockFree,
	"IsDestroyed": lockFree, "Cap": lockFree, "SlotSize": lockFree, "Capabilities": lockFree,
	"String": lockFree, "GoString": lockFree, "Format": lockFree, "LogValue": lockFree,
}

// checkReentrancy flags an access method called on the SAME buffer inside its
// own borrowing closure. A DIFFERENT buffer (the documented decrypt-into
// pattern) is resolved by object identity and is not flagged.
//
// Receivers are compared as identity chains, so a buffer held in a struct
// field is covered, and a local bound once to the buffer (b2 := buf) or to
// one of its methods (l := buf.Len) resolves to the buffer. A buffer embedded
// in a struct is the same buffer whether its method is called through the
// promotion (e.Len()) or on the field (e.SecureBuffer.Len()).
//
// Only calls that run synchronously inside the closure count. A func literal
// that is assigned, returned, sent or launched with go runs after the lease
// (or on another goroutine) and is skipped; one that is invoked in place,
// deferred, or passed to a call is walked.
func (c *checker) checkReentrancy(acc accessor) {
	if acc.recvExpr == nil {
		return // a method value bound to several receivers: identity undecidable
	}
	slot := namedTypeKey(c.pass.TypesInfo.TypeOf(acc.recvExpr)) == secmemPkg+".ArenaSlot"
	if len(acc.recv) == 0 && !slot {
		return
	}
	arena, arenaKnown := c.slotArena(acc)
	kind := "buffer"
	switch {
	case slot:
		kind = "slot"
	case acc.method.Pkg() != nil && acc.method.Pkg().Path() == cryptoPkg:
		kind = "key"
	}

	var stack []ast.Node
	ast.Inspect(acc.body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if lit, ok := n.(*ast.FuncLit); ok && !runsSynchronously(lit, stack) {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		mc, ok := c.methodCallOf(call)
		if !ok || mc.recv == nil {
			return true
		}
		name := mc.method.Name()
		if takesReceiverLock(mc.method) {
			if inner, ok := c.receiverKeyOf(mc); ok && sameReceiver(acc.recv, inner) {
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on the same %s inside its own borrowing closure; secmem access methods are not reentrant and will deadlock",
					name, kind))
				return true
			}
		}
		if slot && arenaLocks[name] == takesLock && namedTypeKey(c.pass.TypesInfo.TypeOf(mc.recv)) == secmemPkg+".SecureArena" {
			inner, ok := c.receiverKeyOf(mc)
			switch {
			case arenaKnown && ok && sameReceiver(arena, inner):
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on the slot's arena inside a slot borrow; it takes the arena's exclusive lock, which the borrow holds for reading, and will deadlock",
					name))
			case !arenaKnown && strict:
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on a SecureArena inside a slot borrow whose arena cannot be resolved; if it is this slot's arena the call will deadlock",
					name))
			}
		}
		return true
	})
}

// slotArena resolves the arena a slot receiver was acquired from — the
// receiver of the Acquire call in slot, err := arena.Acquire() — when the slot
// is a local bound exactly once that way.
func (c *checker) slotArena(acc accessor) ([]types.Object, bool) {
	if len(acc.recv) != 1 {
		return nil, false
	}
	v, ok := acc.recv[0].(*types.Var)
	if !ok {
		return nil, false
	}
	call, idx, ok := c.defs.singleTupleDef(v)
	if !ok || idx != 0 {
		return nil, false
	}
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Acquire" {
		return nil, false
	}
	if namedTypeKey(c.pass.TypesInfo.TypeOf(sel.X)) != secmemPkg+".SecureArena" {
		return nil, false
	}
	return c.receiverKey(sel.X, 0)
}

// runsSynchronously reports whether a func literal (the last node on stack)
// executes before its enclosing closure returns: it is invoked in place,
// deferred, or passed as an argument to a call that is not a go statement.
func runsSynchronously(lit *ast.FuncLit, stack []ast.Node) bool {
	if len(stack) < 2 {
		return true
	}
	parent := stack[len(stack)-2]
	call, ok := parent.(*ast.CallExpr)
	if !ok {
		return false // assigned, returned, sent, stored in a literal
	}
	if len(stack) >= 3 {
		if _, ok := stack[len(stack)-3].(*ast.GoStmt); ok {
			return false
		}
	}
	_ = lit
	return call != nil
}
