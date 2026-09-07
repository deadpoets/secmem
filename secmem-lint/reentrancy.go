package secmemlint

import (
	"fmt"
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// reentrantUnsafe is the set of secmem access methods that take the buffer's
// lock. Calling any of them on the SAME buffer from inside its own borrowing
// closure violates the documented non-reentrancy contract and deadlocks.
var reentrantUnsafe = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"WithBytes": true, "WithBytesErr": true,
	"WithScalar": true, "WithSeed": true, "WithDER": true,
	"CopyOut": true, "CopyIn": true, "ConstantTimeEqual": true,
	"ExposeString": true, "ByteAt": true, "WriteTo": true, "ReadFrom": true,
	"Truncate": true, "Seal": true, "Unseal": true,
	"ReadOnly": true, "ReadWrite": true, "Destroy": true,

	// SetByteAt takes the EXCLUSIVE lock, so calling it inside a borrow is an
	// unconditional self-deadlock — the most certain member of this set, and it
	// was missing while its read counterpart ByteAt was listed.
	"SetByteAt": true,

	// The rLock inspectors. A nested read acquire looks harmless, but this
	// package's lock is writer-preferring: rLock waits while any writer is
	// queued, so a second read taken from inside a borrow deadlocks as soon as
	// a writer arrives between the two — a Destroy or an emergency wipe is
	// enough. That makes them load-bearing rather than merely untidy.
	"Len": true, "MappedLen": true, "IsSealed": true, "IsDestroyed": true,
}

// checkReentrancy flags an access method called on the SAME buffer inside its own
// borrowing closure. A DIFFERENT buffer (the documented decrypt-into pattern) is
// resolved by object identity and is not flagged.
//
// Receivers are compared as identity chains, so a buffer held in a struct field
// is covered. Requiring a plain identifier on both ends — which is all this
// check used to do — silently disabled it for s.buf.WithBytes(...), and holding
// the buffer in a struct is how most programs of any size hold it.
func checkReentrancy(pass *analysis.Pass, acc accessor, sup *suppressor) {
	if len(acc.recv) == 0 {
		return
	}
	ast.Inspect(acc.fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !reentrantUnsafe[sel.Sel.Name] {
			return true
		}
		inner, ok := receiverKey(pass, sel.X)
		if !ok || !sameReceiver(acc.recv, inner) {
			return true
		}
		if !sup.suppressed(pass, call.Pos()) {
			report(pass, call.Pos(), fmt.Sprintf(
				"%s called on the same buffer inside its own borrowing closure; secmem access methods are not reentrant and will deadlock",
				sel.Sel.Name))
		}
		return true
	})
}
